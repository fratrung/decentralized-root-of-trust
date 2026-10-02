# Validate the measurement schema, the complete per-run sample grid, and that
# every per-run statistic in runs.csv is the one its own samples give.
# Usage: awk -v targets="..." -v expected_runs=N -v expected_items=M \
#            -f tools/validate_benchmark_csv.awk runs.csv samples.csv
#
# The binaries compute each run's median/mean/sd/min/max/total from unrounded
# timings and print both those statistics and every sample with three decimals.
# Recomputing from the printed samples therefore differs only by rounding:
# at most 0.0005 ms per sample plus 0.0005 ms for the printed statistic. The
# tolerances below cover exactly that (a total accumulates one half-unit per
# sample); anything larger means runs.csv and samples.csv do not describe the
# same measurements. Presence and format alone would accept an impossible
# median as long as it is numeric.
function stat_fields(target, phase, list) {
    stats_of[target, phase] = list
}
BEGIN {
    # phase -> the runs.csv statistics derived from it, as `prefix:kind`
    # (`full` = med mean sd min max total; `medtot` = med total).
    stat_fields("signer", "sign_protocol", "sign:full")
    stat_fields("signer", "slot_burn", "slot_burn:medtot")
    stat_fields("signer", "sign_crypto", "sign_crypto:medtot")
    stat_fields("mldsa_signer", "sign_crypto", "sign:full sign_crypto:medtot")
    stat_fields("prover", "prove", "prove:full")
    # CPU of the same intervals, from the process CPU clock: one `*_cpu` phase
    # per target, summarized as median and total.
    stat_fields("signer", "sign_protocol_cpu", "sign_cpu:medtot")
    stat_fields("mldsa_signer", "sign_crypto_cpu", "sign_cpu:medtot")
    stat_fields("prover", "prove_cpu", "prove_cpu:medtot")
    split("verifier raw_agg mldsa_raw_agg", receivers, " ")
    for (i = 1; i <= 3; i++) {
        stat_fields(receivers[i], "decode", "decode:full")
        stat_fields(receivers[i], "verify", "verify:full")
        stat_fields(receivers[i], "decode_verify", "decode_verify:full")
        stat_fields(receivers[i], "decode_verify_cpu", "decode_verify_cpu:medtot")
    }
    # The phase whose `bytes` artifact_med_bytes is the median of. The verifier
    # reports no artifact size.
    bytes_phase["signer"] = "sign_protocol"
    bytes_phase["mldsa_signer"] = "sign_crypto"
    bytes_phase["prover"] = "prove"
    bytes_phase["raw_agg"] = "decode"
    bytes_phase["mldsa_raw_agg"] = "decode"
}
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
            phases[target, "sign_protocol_cpu"] = 1
        } else if (target == "mldsa_signer") {
            phases[target, "sign_crypto"] = 1
            phases[target, "sign_crypto_cpu"] = 1
        } else if (target == "prover") {
            phases[target, "prove"] = 1
            phases[target, "prove_cpu"] = 1
        } else if (target == "verifier" || target == "raw_agg" ||
                   target == "mldsa_raw_agg") {
            phases[target, "decode"] = 1
            phases[target, "verify"] = 1
            phases[target, "decode_verify"] = 1
            phases[target, "decode_verify_cpu"] = 1
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
    run_line[target, run] = $0
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
        required("sign_cpu_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "mldsa_signer") {
        required("keygen_ms", 0)
        required("sign_med_ms", 0)
        required("sign_cpu_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "prover") {
        required("setup_ms", 0)
        required("prove_med_ms", 0)
        required("prove_cpu_med_ms", 0)
        required("artifact_med_bytes", 1)
    } else if (target == "verifier") {
        required("setup_ms", 0)
        required("decode_med_ms", 0)
        required("verify_med_ms", 0)
        required("decode_verify_med_ms", 0)
        required("decode_verify_cpu_med_ms", 0)
    } else if (target == "raw_agg" || target == "mldsa_raw_agg") {
        required("decode_med_ms", 0)
        required("verify_med_ms", 0)
        required("decode_verify_med_ms", 0)
        required("decode_verify_cpu_med_ms", 0)
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
    n = ++sample_count[target, run, phase]
    sample_ms[target, run, phase, n] = $(sample_col["ms"])
    sample_bytes[target, run, phase, n] = $(sample_col["bytes"])
    if (!decimal($(sample_col["ms"])) || !decimal($(sample_col["bytes"])) ||
        $(sample_col["bytes"]) + 0 <= 0 || !decimal($(sample_col["rss_mb"])))
        fail("invalid numeric sample at line " FNR)
    next
}
# Sort one run's values for one phase into sorted[1..n] (insertion sort: n is
# the per-run item count, about twenty).
function collect(store, target, run, phase, n,    i, j, x) {
    for (i = 1; i <= n; i++) {
        x = store[target, run, phase, i] + 0
        for (j = i - 1; j >= 1 && sorted[j] > x; j--) sorted[j + 1] = sorted[j]
        sorted[j + 1] = x
    }
}
function median_of(n) {
    return (n % 2) ? sorted[(n + 1) / 2] : (sorted[n / 2] + sorted[n / 2 + 1]) / 2
}
function abs(x) { return x < 0 ? -x : x }
# Compare one reported statistic with its recomputed value, if runs.csv has
# that column at all (the unit-test fixtures carry a subset).
function agree(fields, target, run, column, expected, tolerance,    reported) {
    if (!(column in run_col)) return
    reported = fields[run_col[column]]
    if (!decimal(reported)) {
        fail(target "/" run ": " column "=" reported " is not a number")
        return
    }
    if (abs(reported - expected) > tolerance)
        fail(target "/" run ": " column "=" reported " but its samples give " \
             sprintf("%.4f", expected))
}
function check_run(target, run,    fields, key, part, phase, n, list, count, k,
                   spec, prefix, kind, i, sum, mean, ss, sd) {
    split(run_line[target, run], fields, ",")
    for (key in stats_of) {
        split(key, part, SUBSEP)
        if (part[1] != target) continue
        phase = part[2]
        n = sample_count[target, run, phase]
        if (n != expected_items) continue   # already reported as a grid error
        collect(sample_ms, target, run, phase, n)
        sum = 0
        for (i = 1; i <= n; i++) sum += sorted[i]
        mean = sum / n
        ss = 0
        for (i = 1; i <= n; i++) ss += (sorted[i] - mean) ^ 2
        sd = (n > 1) ? sqrt(ss / (n - 1)) : 0
        count = split(stats_of[key], list, " ")
        for (k = 1; k <= count; k++) {
            split(list[k], spec, ":")
            prefix = spec[1]; kind = spec[2]
            agree(fields, target, run, prefix "_med_ms", median_of(n), 0.002)
            agree(fields, target, run, prefix "_total_ms", sum, 0.0005 * n + 0.002)
            if (kind != "full") continue
            agree(fields, target, run, prefix "_mean_ms", mean, 0.002)
            agree(fields, target, run, prefix "_sd_ms", sd, 0.002)
            agree(fields, target, run, prefix "_min_ms", sorted[1], 0.002)
            agree(fields, target, run, prefix "_max_ms", sorted[n], 0.002)
        }
    }
    if (target in bytes_phase) {
        phase = bytes_phase[target]
        n = sample_count[target, run, phase]
        if (n == expected_items) {
            collect(sample_bytes, target, run, phase, n)
            agree(fields, target, run, "artifact_med_bytes", median_of(n), 0.5)
        }
    }
}
END {
    for (i = 1; i <= target_count; i++) {
        target = target_names[i]
        if (run_count[target] != run_limit[target])
            fail("target " target " has " run_count[target] " runs; expected " run_limit[target])
        for (run = 1; run <= run_limit[target]; run++) {
            if (run_seen[target, run] != 1)
                fail("missing run " target "/" run)
            else
                check_run(target, run)
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
