#!/usr/bin/env bash
#
# Driver for the two container demos.
#
#   ./demo.sh raw   up        build the image and start the network + node A
#   ./demo.sh raw   round     node A asks for a credential, then verifies it
#   ./demo.sh raw   verify    verify whatever is published, without a new round
#   ./demo.sh raw   crash     kill a member mid-protocol and watch it re-align
#   ./demo.sh raw   logs      follow every node
#   ./demo.sh raw   down      stop the network and delete its volumes
#
# `snark` in place of `raw` runs the same network publishing one aggregated
# proof instead of the signatures. The two share a subnet, so `up` tears the
# other one down first.
#
# Node A is resident: `up` starts it, it does its one-time setup there, and
# `round` and `verify` only send it a trigger. That is why the SNARK setup cost
# appears once, in `up`, instead of in front of every verification.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-raw}"
CMD="${2:-help}"

case "$MODE" in
  raw)   OTHER=snark ;;
  snark) OTHER=raw ;;
  *) echo "usage: $0 {raw|snark} {up|round|verify|crash|logs|ps|down}" >&2; exit 2 ;;
esac

COMPOSE=(docker compose -f "$HERE/compose.$MODE.yml")
OTHER_COMPOSE=(docker compose -f "$HERE/compose.$OTHER.yml")

# The victim of the crash scenario. Any member will do: none of them is special,
# which is the property the scenario is there to show.
VICTIM="${VICTIM:-3}"
THRESHOLD=7

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m   PASS\033[0m %s\n' "$*"; }
bad() { printf '\033[31m   FAIL\033[0m %s\n' "$*"; exit 1; }

# Runs a shell inside a throwaway container that has both shared volumes
# mounted, which is the only way to look at them without a node.
in_volumes() { "${COMPOSE[@]}" run --rm --no-deps --entrypoint sh probe -c "$1"; }

wait_for_anchor() {
  in_volumes 'for i in $(seq 1 180); do [ -s /shared/committee/anchor.bin ] && exit 0; sleep 1; done; exit 1' \
    || bad "the committee was never assembled; try: $0 $MODE logs"
}

published_count() {
  in_volumes 'ls /shared/storage/status-*.ssz 2>/dev/null | wc -l' | tr -dc '0-9'
}

# A member's own log, which is where its side of the protocol is visible.
victim_log() { docker logs "drot-$MODE-signer-$VICTIM" 2>&1; }

# Node A's log, where the report of every round it ran is printed.
holder_log() { docker logs "drot-$MODE-holder" 2>&1; }

# `grep -c` and not `grep -q`: under `pipefail` a `-q` that matches early kills
# `docker logs` with SIGPIPE, and the pipeline then reports the failure of the
# write rather than the success of the match.
wait_for_holder() {
  local deadline=$((SECONDS + 600))
  until [ "$(holder_log | grep -c 'resident on' || true)" -gt 0 ]; do
    [ "$SECONDS" -lt "$deadline" ] || bad "node A never finished its setup; try: $0 $MODE logs"
    sleep 1
  done
}

# Triggers one round on the resident node A and shows what it printed.
#
# The report is fetched from node A's log rather than sent back over the wire:
# it is the relying party's own account of what it checked, and moving it would
# only make it look like something the trigger was told.
fire() {
  local before status=0
  wait_for_holder
  before="$(holder_log | wc -l)"
  # stdout of the trigger is dropped, stderr kept: its verdict is the last line
  # of the log we are about to print anyway, but a trigger that cannot reach
  # node A at all has to stay visible.
  "${COMPOSE[@]}" run --rm --no-deps -e "HOLDER_TRIGGER=$1" trigger >/dev/null || status=$?
  holder_log | tail -n +$((before + 1))
  return "$status"
}

wait_until_ready() {
  local before="$1" deadline=$((SECONDS + 120))
  while [ "$(victim_log | grep -c 'ready on' || true)" -le "$before" ]; do
    [ "$SECONDS" -lt "$deadline" ] || bad "member $VICTIM did not come back up"
    sleep 1
  done
}

case "$CMD" in
  build)
    "${COMPOSE[@]}" build
    ;;

  up)
    say "clearing the $OTHER demo, which shares this subnet"
    "${OTHER_COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
    say "starting the $MODE network: 1 bootstrap + 10 members, threshold $THRESHOLD"
    "${COMPOSE[@]}" up -d --build
    wait_for_anchor
    say "waiting for node A to finish its one-time verifier setup"
    wait_for_holder
    holder_log | tail -n +2
    say "the committee is assembled, every member is listening, node A is ready"
    "${COMPOSE[@]}" ps
    ;;

  round)
    fire round
    ;;

  verify)
    fire verify
    ;;

  logs)
    "${COMPOSE[@]}" logs -f
    ;;

  ps)
    "${COMPOSE[@]}" ps
    ;;

  down)
    "${COMPOSE[@]}" down -v --remove-orphans
    ;;

  crash)
    # Does a durable slot burn survive the machine it was made on?
    #
    # The member signs, is killed without warning, comes back, and is asked to
    # sign a *different* list at the same version. If the burn were in memory it
    # would say yes, and two signatures at one XMSS slot recover its secret key.
    say "scenario: member $VICTIM crashes between two proposals"

    if [ "$(published_count)" -eq 0 ]; then
      say "step 0: nothing is published yet, running one normal round"
      fire round >/dev/null
    fi

    say "step 1: member $VICTIM signs the next version (nobody publishes it)"
    # A run that ended between step 1 and step 5 leaves the victim holding a
    # burned slot for a version nobody published, and it is right to refuse it a
    # second time. Publishing one version moves the target forward, which is the
    # same recovery step 6 relies on.
    if ! "${COMPOSE[@]}" run --rm --no-deps probe --member "$VICTIM" --entry pre-crash; then
      say "that version was spent by an earlier run; publishing one round and retrying"
      fire round >/dev/null
      "${COMPOSE[@]}" run --rm --no-deps probe --member "$VICTIM" --entry pre-crash \
        || bad "the member should have signed here"
    fi
    ok "signed, so the slot for that version is now spent on disk"

    say "step 2: SIGKILL, no shutdown hook, no chance to flush anything"
    docker kill -s KILL "drot-$MODE-signer-$VICTIM" >/dev/null
    ready_before="$(victim_log | grep -c 'ready on' || true)"
    sleep 1

    say "step 3: restart, and let it resume from whatever is on its volume"
    docker start "drot-$MODE-signer-$VICTIM" >/dev/null
    wait_until_ready "$ready_before"
    victim_log | grep 'counter resumed' | tail -1

    say "step 4: same version, different list. This is the double-sign attempt"
    set +e
    "${COMPOSE[@]}" run --rm --no-deps probe --member "$VICTIM" --entry post-crash
    status=$?
    set -e
    [ "$status" -eq 3 ] \
      && ok "refused after the crash: the slot was burned before the key touched it" \
      || bad "expected an abstention (exit 3), got exit $status"

    say "step 5: a normal round. The committee does not need this member"
    fire round >/dev/null \
      && ok "quorum reached without member $VICTIM, which is what t < N is for" \
      || bad "the round should still have succeeded"
    victim_log | grep 'abstains' | tail -1

    say "step 6: the next round, at a version the member has not signed"
    signed_before="$(victim_log | grep -c 'signed v' || true)"
    fire round >/dev/null
    if [ "$(victim_log | grep -c 'signed v' || true)" -gt "$signed_before" ]; then
      ok "member $VICTIM is signing again, re-aligned by deriving the slot from the anchor"
      victim_log | grep 'signed v' | tail -1
    else
      bad "member $VICTIM never rejoined"
    fi

    say "scenario complete"
    ;;

  *)
    sed -n '3,18p' "$0"
    ;;
esac
