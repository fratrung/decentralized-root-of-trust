# Validate the measurement schema and the complete per-run sample grid.
# Usage: awk -v targets="..." -v expected_runs=N -v expected_items=M \
#            -f tools/validate_benchmark_csv.awk runs.csv samples.csv
BEGIN {
    target_count = split(targets, target_names, " ")
    count_count = split(run_counts, count_pairs, " ")
    for (i = 1; i <= count_count; i++) {
        split(count_pairs[i], pair, ":")
        if (pair[1] != "") run_limit[pair[1]] = pair[2] + 0
    }
    for (i = 1; i <= target_count; i++) {
        target = target_names[i]
        allowed[target] = 1
        if (!(target in run_limit)) run_limit[target] = expected_runs
        if (target == "signer") {
            phases[target, "sign_protocol"] = 1
            phases[target, "slot_burn"] = 1
            phases[target, "sign_crypto"] = 1
        } else if (target == "mldsa_signer") {
            phases[target, "sign_crypto"] = 1
        } else if (target == "prover") {
            phases[target, "prove"] = 1
        } else if (target == "verifier" || target == "raw_agg" ||
                   target == "mldsa_raw_agg") {
            phases[target, "decode"] = 1
            phases[target, "verify"] = 1
            phases[target, "decode_verify"] = 1
        }
    }
}
function fail(message) {
    if (++errors <= 8) print "invalid benchmark CSV: " message > "/dev/stderr"
}
function decimal(value) {
    return value ~ /^[0-9]+([.][0-9]+)?$/
}
function required(field, positive, value) {
    if (!(field in run_col)) {
        fail("missing runs.csv column " field)
        return
    }
    value = $(run_col[field])
    if (!decimal(value) || (positive && value + 0 <= 0))
        fail("line " FNR " target " $1 ": invalid " field "=" value)
}
FILENAME == ARGV[1] {
    if (FNR == 1) {
        run_columns = NF
        for (i = 1; i <= NF; i++) run_col[$i] = i
        next
    }
    target = $(run_col["target"])
    run = $(run_col["run"])
    if (NF != run_columns) fail("runs.csv line " FNR " has wrong column count")
    if (!(target in allowed)) { if (!allow_extra) fail("unexpected target " target); next }
    if (run !~ /^[1-9][0-9]*$/ || run + 0 > run_limit[target]) {
        fail("invalid run ID for " target ": " run)
        next
    }
    if (++run_seen[target, run] != 1) fail("duplicate run " target "/" run)
    run_count[target]++
    if ($(run_col["n_items"]) != expected_items)
        fail("wrong n_items for " target "/" run)
    if ($(run_col["failures"]) != "0")
        fail("failed or missing security gate for " target "/" run)
    required("peak_rss_mb", 0)
    if (target == "signer") {
        required("keygen_ms", 0)
        required("slot_state_ms", 0)
        required("sign_med_ms", 0)
        required("slot_burn_med_ms", 0)
        required("sign_crypto_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "mldsa_signer") {
        required("keygen_ms", 0)
        required("sign_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "prover") {
        required("setup_ms", 0)
        required("prove_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "verifier") {
        required("setup_ms", 0)
        required("decode_med_ms", 0)
        required("verify_med_ms", 0)
        required("decode_verify_med_ms", 0)
    } else if (target == "raw_agg" || target == "mldsa_raw_agg") {
        required("decode_med_ms", 0)
        required("verify_med_ms", 0)
        required("decode_verify_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "combined") {
        required("setup_ms", 0)
        required("prove_med_ms", 0)
        required("verify_med_ms", 0)
        required("artifact_med_bytes", 1)
    }
    next
}
FILENAME == ARGV[2] {
    if (FNR == 1) {
        sample_columns = NF
        for (i = 1; i <= NF; i++) sample_col[$i] = i
        next
    }
    target = $(sample_col["target"])
    run = $(sample_col["run"])
    phase = $(sample_col["phase"])
    sample_index = $(sample_col["idx"])
    if (NF != sample_columns) fail("samples.csv line " FNR " has wrong column count")
    if (!(target in allowed) || !((target, phase) in phases)) {
        if (!allow_extra || (target in allowed))
            fail("unexpected sample target/phase " target "/" phase)
        next
    }
    if (run !~ /^[1-9][0-9]*$/ || run + 0 > run_limit[target] ||
        sample_index !~ /^(0|[1-9][0-9]*)$/ || sample_index + 0 >= expected_items) {
        fail("invalid sample run/index for " target "/" phase)
        next
    }
    if (++sample_seen[target, run, phase, sample_index] != 1)
        fail("duplicate sample " target "/" run "/" phase "/" sample_index)
    sample_count[target, run, phase]++
    if (!decimal($(sample_col["ms"])) || !decimal($(sample_col["bytes"])) ||
        $(sample_col["bytes"]) + 0 <= 0 || !decimal($(sample_col["rss_mb"])))
        fail("invalid numeric sample at line " FNR)
    next
}
END {
    for (i = 1; i <= target_count; i++) {
        target = target_names[i]
        if (run_count[target] != run_limit[target])
            fail("target " target " has " run_count[target] " runs; expected " run_limit[target])
        for (run = 1; run <= run_limit[target]; run++) {
            if (run_seen[target, run] != 1)
                fail("missing run " target "/" run)
            for (key in phases) {
                split(key, part, SUBSEP)
                if (part[1] != target) continue
                phase = part[2]
                if (sample_count[target, run, phase] != expected_items)
                    fail("target " target " run " run " phase " phase " has " \
                         sample_count[target, run, phase] " samples; expected " expected_items)
            }
        }
    }
    if (errors > 8) print "invalid benchmark CSV: " errors - 8 " further errors" > "/dev/stderr"
    if (errors) exit 1
}
