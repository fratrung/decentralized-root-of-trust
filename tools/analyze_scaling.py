#!/usr/bin/env python3
"""Block-aware analysis of a committee-scaling campaign.

    tools/analyze_scaling.py committee-scaling-<timestamp>

The scaling report summarizes every comparison with one 95% interval that
treats all paired runs of a point as independent and looks at one comparison at
a time. This tool reads the same runs (`all-runs.csv`) and answers the three
questions that interval leaves open:

1. Sessions. The runs of a point come from several sessions (one per sweep),
   each a separate build, fixture and stretch of time. Runs of one session
   share its thermal state, clock frequency and keys, so they are not
   independent of one another. For every quantity the tool separates the
   variation between sessions from the variation inside them (one-way analysis
   of variance), tests the session effect, and gives three intervals for a mean:
     pairs            every run independent (the report's interval);
     within_sessions  sessions as fixed blocks: their shifts are removed from
                      the error, and the statement is about these sessions;
     sessions         sessions as the unit of replication: the statement is
                      about another session on this host. It has S - 1 degrees
                      of freedom, so with two sweeps it is wide unless the two
                      sessions agree closely.
2. Time. Inside a session the runs are ordered. A least-squares slope of each
   quantity against the run order, with its interval, shows a drift; the lag-1
   autocorrelation of the residuals shows runs that follow their predecessor.
3. Multiplicity. A campaign reports several comparisons at several committee
   sizes. Holm-adjusted p-values and Bonferroni simultaneous intervals keep the
   95% level for the whole family instead of for each line alone.

It chooses no threshold and no scheme: the 95% level is the one the harness
already uses, and every figure is a description of the measured runs.

No third-party package is required. Output, in <campaign>/analysis by default:
  blocks.csv       session effect on every role's cost
  trends.csv       drift and autocorrelation inside every session
  comparisons.csv  the paired differences under every interval above
  report.txt       the same as tables, with the first observed points
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

LEVEL = 0.95

# target -> role name used in the scaling layer's tidy files
ROLES = {
    "prover": "prover",
    "verifier": "snark_verifier",
    "raw_agg": "xmss_raw_verifier",
    "mldsa_raw_agg": "mldsa_raw_verifier",
}
# clock -> runs.csv column holding the per-run median of the timed phase
PROVE = {"elapsed": "prove_med_ms", "cpu": "prove_cpu_med_ms"}
VERIFY = {"elapsed": "decode_verify_med_ms", "cpu": "decode_verify_cpu_med_ms"}
# (a, b): delta = a - b on the per-run medians of decode + verify
COMPARISONS = (("raw_agg", "verifier"), ("mldsa_raw_agg", "verifier"), ("raw_agg", "mldsa_raw_agg"))
SHORT = {"verifier": "snark", "raw_agg": "xmss_raw", "mldsa_raw_agg": "mldsa_raw"}


# ------------------------------------------------------------ distributions --
def _beta_continued_fraction(a: float, b: float, x: float) -> float:
    """Continued fraction of the incomplete beta function (modified Lentz)."""
    tiny = 1e-300
    c, d = 1.0, 1.0 - (a + b) * x / (a + 1.0)
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 10_000):
        for numerator in (m * (b - m) * x / ((a + 2 * m - 1) * (a + 2 * m)),
                          -(a + m) * (a + b + m) * x / ((a + 2 * m) * (a + 2 * m + 1))):
            d = 1.0 + numerator * d
            d = 1.0 / (d if abs(d) > tiny else tiny)
            c = 1.0 + numerator / c
            c = c if abs(c) > tiny else tiny
            h *= d * c
        if abs(d * c - 1.0) < 1e-15:
            return h
    raise ArithmeticError("incomplete beta function did not converge")


def beta_regularized(a: float, b: float, x: float) -> float:
    """I_x(a, b), the regularized incomplete beta function."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                     + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _beta_continued_fraction(a, b, x) / a
    return 1.0 - front * _beta_continued_fraction(b, a, 1.0 - x) / b


def t_two_sided_p(statistic: float, df: int) -> float:
    """P(|T| >= |statistic|) for Student's t with `df` degrees of freedom."""
    if math.isinf(statistic):
        return 0.0
    return beta_regularized(df / 2.0, 0.5, df / (df + statistic * statistic))


def t_quantile(confidence: float, df: int) -> float:
    """The x with P(|T| <= x) = confidence, by bisection on the distribution."""
    low, high = 0.0, 1.0
    while t_two_sided_p(high, df) > 1.0 - confidence:
        high *= 2.0
    for _ in range(200):
        middle = (low + high) / 2.0
        if t_two_sided_p(middle, df) > 1.0 - confidence:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def f_upper_p(statistic: float, df1: int, df2: int) -> float:
    """P(F >= statistic) for the F distribution with (df1, df2) degrees of freedom."""
    if math.isinf(statistic):
        return 0.0
    if statistic <= 0.0:
        return 1.0
    return beta_regularized(df2 / 2.0, df1 / 2.0, df2 / (df2 + df1 * statistic))


# ---------------------------------------------------------------- estimates --
def mean(values: list[float]) -> float:
    return sum(values) / len(values)


def interval(center: float, standard_error: float, df: int, confidence: float = LEVEL):
    """(low, high), or None when the interval cannot be estimated."""
    if df < 1:
        return None
    half = t_quantile(confidence, df) * standard_error
    return center - half, center + half


def p_value(center: float, standard_error: float, df: int) -> float | None:
    """Two-sided p-value of H0: mean = 0, or None when it cannot be estimated."""
    if df < 1:
        return None
    if standard_error == 0.0:
        return 1.0 if center == 0.0 else 0.0
    return t_two_sided_p(center / standard_error, df)


def blocks(sessions: list[list[float]]) -> dict[str, object]:
    """One-way analysis of variance of balanced sessions.

    `sessions` holds the per-run values of each session. Returns the grand
    mean, the session means, the mean squares between and inside sessions, the
    F test of the session effect, the intraclass correlation, and the standard
    error and degrees of freedom of the grand mean under the three readings
    described in the module docstring.
    """
    count = len(sessions)
    runs = len(sessions[0])
    if any(len(session) != runs for session in sessions):
        raise ValueError("sessions are not balanced")
    total = count * runs
    values = [value for session in sessions for value in session]
    grand = mean(values)
    session_means = [mean(session) for session in sessions]
    between = runs * sum((m - grand) ** 2 for m in session_means)
    within = sum((value - m) ** 2 for session, m in zip(sessions, session_means) for value in session)
    df_between, df_within = count - 1, count * (runs - 1)
    ms_between = between / df_between if df_between else None
    ms_within = within / df_within if df_within else None
    result: dict[str, object] = {
        "sessions": count, "runs": runs, "mean": grand, "session_means": session_means,
        "ms_between": ms_between, "ms_within": ms_within,
        "f": None, "f_p": None, "icc": None,
        # standard error and degrees of freedom of the grand mean
        "pairs": (math.sqrt((between + within) / (total - 1) / total), total - 1) if total > 1 else (None, 0),
        "within_sessions": (math.sqrt(ms_within / total), df_within) if ms_within is not None else (None, 0),
        "sessions_unit": (math.sqrt(ms_between / total), df_between) if ms_between is not None else (None, 0),
    }
    if ms_between is not None and ms_within is not None:
        if ms_within > 0.0:
            result["f"] = ms_between / ms_within
            result["f_p"] = f_upper_p(result["f"], df_between, df_within)
        elif ms_between > 0.0:
            result["f"], result["f_p"] = math.inf, 0.0
        denominator = ms_between + (runs - 1) * ms_within
        if denominator > 0.0:
            result["icc"] = max(0.0, (ms_between - ms_within) / denominator)
    return result


def trend(values: list[float]) -> dict[str, float | None]:
    """Least-squares slope of `values` against their order 1..n.

    Returns the slope, its standard error and degrees of freedom, and the lag-1
    autocorrelation of the residuals. Fewer than three values leave no degree
    of freedom for the error, and the slope is not estimated.
    """
    n = len(values)
    result: dict[str, float | None] = {"n": n, "mean": mean(values), "slope": None, "se": None, "df": n - 2, "lag1": None}
    if n < 3:
        return result
    xs = list(range(1, n + 1))
    x_mean, y_mean = mean(xs), mean(values)
    sxx = sum((x - x_mean) ** 2 for x in xs)
    slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, values)) / sxx
    residuals = [y - (y_mean + slope * (x - x_mean)) for x, y in zip(xs, values)]
    squares = sum(r * r for r in residuals)
    result["slope"] = slope
    result["se"] = math.sqrt(squares / (n - 2) / sxx)
    if squares > 0.0:
        result["lag1"] = sum(a * b for a, b in zip(residuals, residuals[1:])) / squares
    return result


def holm(p_values: list[float | None]) -> list[float | None]:
    """Holm step-down adjusted p-values; entries that are None stay None."""
    known = sorted((p, index) for index, p in enumerate(p_values) if p is not None)
    adjusted: list[float | None] = [None] * len(p_values)
    running = 0.0
    for rank, (p, index) in enumerate(known):
        running = max(running, min(1.0, (len(known) - rank) * p))
        adjusted[index] = running
    return adjusted


def sign(bounds) -> str:
    """Which side of zero an interval of `a - b` lies on."""
    if bounds is None:
        return "no_interval"
    low, high = bounds
    return "a_slower" if low > 0 else "b_slower" if high < 0 else "not_confirmed"


# -------------------------------------------------------------------- input --
def load(campaign: Path):
    """Read all-runs.csv into {n: {sweep: {target: {run: row}}}} and check it is balanced."""
    source = campaign / "all-runs.csv"
    if not source.is_file():
        raise ValueError(f"{source} not found: not a committee-scaling campaign with completed points")
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        needed = {"n", "t", "list_entries", "sweep", "sweep_direction", "target", "run", "t_start",
                  *PROVE.values(), *VERIFY.values()}
        missing = needed - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{source}: missing columns {', '.join(sorted(missing))}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"{source}: no completed point")
    points: dict[int, dict[int, dict[str, dict[int, dict[str, str]]]]] = {}
    for row in rows:
        target = points.setdefault(int(row["n"]), {}).setdefault(int(row["sweep"]), {}).setdefault(row["target"], {})
        run = int(row["run"])
        if run in target:
            raise ValueError(f"{source}: N={row['n']} sweep {row['sweep']} {row['target']} run {run} appears twice")
        target[run] = row
    shapes = set()
    for n, sweeps in points.items():
        for sweep, targets in sweeps.items():
            if set(targets) != set(ROLES):
                raise ValueError(f"{source}: N={n} sweep {sweep} has targets {sorted(targets)}, expected {sorted(ROLES)}")
            run_sets = {frozenset(runs) for runs in targets.values()}
            if len(run_sets) != 1:
                raise ValueError(f"{source}: N={n} sweep {sweep} has targets with different runs")
            shapes.add((len(sweeps), len(next(iter(run_sets)))))
    if len(shapes) != 1:
        raise ValueError(f"{source}: points differ in sweeps or runs per session {sorted(shapes)}; the design is not balanced")
    return points, rows[0]["list_entries"]


def number(row: dict[str, str], column: str, where: str) -> float:
    try:
        value = float(row[column])
    except ValueError:
        raise ValueError(f"{where}: {column} is not a number ({row[column]!r})") from None
    if not math.isfinite(value):
        raise ValueError(f"{where}: {column} is not finite")
    return value


# ----------------------------------------------------------------- analysis --
def analyze(points, list_entries: str):
    block_rows, trend_rows, comparison_rows = [], [], []
    for n in sorted(points):
        sweeps = points[n]
        order = sorted(sweeps)
        t = next(iter(sweeps[order[0]]["prover"].values()))["t"]
        directions = [next(iter(sweeps[s]["prover"].values()))["sweep_direction"] for s in order]
        for target, role in ROLES.items():
            for clock in ("elapsed", "cpu"):
                column = (PROVE if target == "prover" else VERIFY)[clock]
                sessions = []
                for sweep in order:
                    runs = sweeps[sweep][target]
                    # time order inside the session: the order the processes started in
                    ordered = sorted(runs.values(), key=lambda row: (float(row["t_start"]), int(row["run"])))
                    values = [number(row, column, f"N={n} sweep {sweep} {target}") for row in ordered]
                    sessions.append(values)
                    fitted = trend(values)
                    slope_ci = None
                    if fitted["slope"] is not None:
                        slope_ci = interval(fitted["slope"], fitted["se"], fitted["df"])
                    base = fitted["mean"]
                    span = len(values) - 1

                    def percent(slope):  # change over the whole session, as % of its mean
                        return None if slope is None or base == 0 else 100.0 * slope * span / base

                    trend_rows.append({
                        "n": n, "t": t, "list_entries": list_entries, "role": role, "clock": clock,
                        "sweep": sweep, "runs": len(values), "mean_ms": base,
                        "slope_ms_per_run": fitted["slope"],
                        "drift_pct": percent(fitted["slope"]),
                        "drift_pct_ci95_low": percent(slope_ci[0]) if slope_ci else None,
                        "drift_pct_ci95_high": percent(slope_ci[1]) if slope_ci else None,
                        "drift": ("no_interval" if slope_ci is None else
                                  "rising" if slope_ci[0] > 0 else "falling" if slope_ci[1] < 0 else "not_confirmed"),
                        "lag1_autocorrelation": fitted["lag1"],
                    })
                summary = blocks(sessions)
                means = summary["session_means"]
                spread = (max(means) - min(means)) / summary["mean"] * 100.0 if summary["mean"] else None
                block_rows.append({
                    "n": n, "t": t, "list_entries": list_entries, "role": role, "clock": clock,
                    "sessions": summary["sessions"], "runs_per_session": summary["runs"],
                    "mean_ms": summary["mean"],
                    "session_means_ms": ";".join(f"{m:.6f}" for m in means),
                    "session_directions": ";".join(directions),
                    "session_spread_pct": spread,
                    "f": summary["f"], "f_p": summary["f_p"], "icc": summary["icc"],
                })
        for a, b in COMPARISONS:
            for clock in ("elapsed", "cpu"):
                column = VERIFY[clock]
                sessions = []
                for sweep in order:
                    runs_a, runs_b = sweeps[sweep][a], sweeps[sweep][b]
                    sessions.append([number(runs_a[run], column, f"N={n} sweep {sweep} {a}")
                                     - number(runs_b[run], column, f"N={n} sweep {sweep} {b}")
                                     for run in sorted(runs_a)])
                summary = blocks(sessions)
                row = {
                    "n": n, "t": t, "list_entries": list_entries, "a": SHORT[a], "b": SHORT[b], "clock": clock,
                    "sessions": summary["sessions"], "runs_per_session": summary["runs"],
                    "delta_mean_ms": summary["mean"],
                    "session_delta_means_ms": ";".join(f"{m:.6f}" for m in summary["session_means"]),
                    "f": summary["f"], "f_p": summary["f_p"], "icc": summary["icc"],
                    "_summary": summary,
                }
                for name in ("pairs", "within_sessions", "sessions_unit"):
                    se, df = summary[name]
                    bounds = interval(summary["mean"], se, df) if se is not None else None
                    label = "sessions" if name == "sessions_unit" else name
                    row[f"{label}_df"] = df
                    row[f"{label}_ci95_low"] = bounds[0] if bounds else None
                    row[f"{label}_ci95_high"] = bounds[1] if bounds else None
                    row[f"{label}_sign"] = sign(bounds)
                    row[f"{label}_p"] = p_value(summary["mean"], se, df) if se is not None else None
                comparison_rows.append(row)
    # Multiplicity: one family holds every comparison of the campaign.
    family = len(comparison_rows)
    for label, name in (("pairs", "pairs"), ("sessions", "sessions_unit")):
        adjusted = holm([row[f"{label}_p"] for row in comparison_rows])
        for row, p_holm in zip(comparison_rows, adjusted):
            se, df = row["_summary"][name]
            bounds = interval(row["delta_mean_ms"], se, df, 1.0 - (1.0 - LEVEL) / family) if se is not None else None
            row[f"{label}_p_holm"] = p_holm
            row[f"{label}_simultaneous_ci95_low"] = bounds[0] if bounds else None
            row[f"{label}_simultaneous_ci95_high"] = bounds[1] if bounds else None
            row[f"{label}_simultaneous_sign"] = sign(bounds)
    for row in comparison_rows:
        row["family_size"] = family
        del row["_summary"]
    return block_rows, trend_rows, comparison_rows


# ------------------------------------------------------------------- output --
def cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return "inf" if math.isinf(value) else f"{value:.6f}"
    return str(value)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow([cell(value) for value in row.values()])


def shown(value, pattern: str = "{:.3f}") -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float) and math.isinf(value):
        return "inf"
    return pattern.format(value)


def bounds_text(row, label: str) -> str:
    low, high = row[f"{label}_ci95_low"], row[f"{label}_ci95_high"]
    return "n/a" if low is None else f"[{low:.3f}, {high:.3f}]"


def report(block_rows, trend_rows, comparison_rows, campaign: Path) -> str:
    first = comparison_rows[0]
    sessions, runs, family = first["sessions"], first["runs_per_session"], first["family_size"]
    sizes = sorted({row["n"] for row in comparison_rows})
    lines = [
        "BLOCK-AWARE ANALYSIS OF A COMMITTEE-SCALING CAMPAIGN",
        f"campaign  : {campaign.name}",
        f"design    : {len(sizes)} committee sizes (N = {', '.join(map(str, sizes))}), list_entries={first['list_entries']},",
        f"            {sessions} sessions per size (one per sweep), {runs} runs per session",
        f"level     : 95%; family of {family} comparisons (committee sizes x verifier pairs x clocks)",
        "",
        "Every interval below is for a mean of per-run medians, in ms. A session is one",
        "sweep's visit to a committee size: its own build, fixture and stretch of time.",
        "",
        "1. SESSION EFFECT ON EACH ROLE'S COST",
        "   spread: (largest - smallest session mean) / mean. F p: probability of a spread",
        "   at least this large if sessions did not differ. ICC: share of the variance",
        "   that lies between sessions; 0 means runs of different sessions are",
        "   interchangeable, 1 means a session fixes the value.",
        f"{'N':>6} {'role':<18} {'clock':<7} {'mean':>12} {'spread':>8} {'F p':>8} {'ICC':>6}  session means",
    ]
    for row in block_rows:
        lines.append(f"{row['n']:>6} {row['role']:<18} {row['clock']:<7} {row['mean_ms']:>12.3f} "
                     f"{shown(row['session_spread_pct'], '{:.2f}%'):>8} {shown(row['f_p'], '{:.4f}'):>8} "
                     f"{shown(row['icc'], '{:.2f}'):>6}  {row['session_means_ms'].replace(';', ' / ')}")
    confirmed = [row for row in trend_rows if row["drift"] in ("rising", "falling")]
    estimable = [row for row in trend_rows if row["drift"] != "no_interval"]
    lines += [
        "",
        "2. DRIFT INSIDE A SESSION",
        "   drift: change of the fitted line from the first to the last run of the",
        "   session, as % of the session mean, with its 95% interval. lag-1: correlation",
        "   of each run's residual with the previous one (0 for independent runs).",
        f"   {len(confirmed)} of {len(estimable)} series have an interval that excludes zero"
        + ("." if estimable else " (too few runs per session to estimate a slope)."),
    ]
    if confirmed:
        lines.append(f"{'N':>6} {'role':<18} {'clock':<7} {'sweep':>5} {'drift':>9} {'95% interval':>22} {'lag-1':>7}")
        for row in confirmed:
            lines.append(f"{row['n']:>6} {row['role']:<18} {row['clock']:<7} {row['sweep']:>5} "
                         f"{row['drift_pct']:>8.2f}% "
                         f"{'[%.2f%%, %.2f%%]' % (row['drift_pct_ci95_low'], row['drift_pct_ci95_high']):>22} "
                         f"{shown(row['lag1_autocorrelation'], '{:.2f}'):>7}")
    lines += [
        "",
        "3. PAIRED DIFFERENCES BETWEEN VERIFIERS (a - b, decode + verify)",
        "   pairs: every paired run independent (the scaling report's interval).",
        "   within: sessions as fixed blocks; a statement about these sessions.",
        f"   sessions: sessions as the unit, {sessions - 1} degree(s) of freedom; a statement about",
        "   another session on this host.",
    ]
    for row in comparison_rows:
        lines.append(f"   N={row['n']:<5} {row['a']} - {row['b']} ({row['clock']}): mean {row['delta_mean_ms']:.3f}, "
                     f"session means {row['session_delta_means_ms'].replace(';', ' / ')}")
        for label, title in (("pairs", "pairs"), ("within_sessions", "within"), ("sessions", "sessions")):
            lines.append(f"      {title:<9} {bounds_text(row, label):>26}  {row[f'{label}_sign']}")
    lines += [
        "",
        f"4. THE WHOLE FAMILY AT ONCE ({family} comparisons)",
        "   Holm p: p-value adjusted so that the chance of any false confirmation in the",
        "   family stays below 5%. simultaneous: Bonferroni interval, all of which cover",
        "   their means together with at least 95% confidence.",
        f"{'N':>6} {'comparison':<22} {'clock':<7} | {'pairs: Holm p':>13} {'simultaneous':>14} | {'sessions: Holm p':>16} {'simultaneous':>14}",
    ]
    for row in comparison_rows:
        lines.append(f"{row['n']:>6} {row['a'] + ' - ' + row['b']:<22} {row['clock']:<7} | "
                     f"{shown(row['pairs_p_holm'], '{:.2e}'):>13} {row['pairs_simultaneous_sign']:>14} | "
                     f"{shown(row['sessions_p_holm'], '{:.2e}'):>16} {row['sessions_simultaneous_sign']:>14}")
    lines += [
        "",
        "5. FIRST OBSERVED POINTS UNDER EACH READING",
        "   The smallest completed N at which b is confirmed faster than a (a_slower),",
        "   and the smallest at which a is confirmed faster (b_slower). '-' : at no",
        "   completed N. Not the exact crossover, and no claim about other N.",
        f"{'comparison':<22} {'clock':<7} {'reading':<24} {'b faster from N':>16} {'a faster from N':>16}",
    ]
    readings = (("pairs_sign", "pairs"), ("within_sessions_sign", "within sessions"), ("sessions_sign", "sessions"),
                ("pairs_simultaneous_sign", "pairs, simultaneous"), ("sessions_simultaneous_sign", "sessions, simultaneous"))
    for a, b in COMPARISONS:
        for clock in ("elapsed", "cpu"):
            subset = [row for row in comparison_rows if row["a"] == SHORT[a] and row["b"] == SHORT[b] and row["clock"] == clock]
            for key, title in readings:
                def first_n(wanted: str) -> str:
                    hits = [row["n"] for row in subset if row[key] == wanted]
                    return str(min(hits)) if hits else "-"
                lines.append(f"{SHORT[a] + ' - ' + SHORT[b]:<22} {clock:<7} {title:<24} {first_n('a_slower'):>16} {first_n('b_slower'):>16}")
    lines += [
        "",
        "Reading guide. A difference confirmed by `pairs` but not by `sessions` is",
        "established for the runs measured, not for another session: more sweeps, not",
        "more runs per session, narrow the `sessions` interval. A session effect (small",
        "F p, ICC well above 0) says runs of one session are not independent, so the",
        "`pairs` interval is too narrow for that quantity. A confirmed drift says the",
        "session mean depends on how long the session ran. None of this extends beyond",
        "this host, list size and set of sessions.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("campaign", type=Path, help="committee-scaling-benchmark.sh output directory")
    parser.add_argument("-o", "--output", type=Path, help="output directory (default: <campaign>/analysis)")
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    output = (args.output or campaign / "analysis").resolve()
    try:
        points, list_entries = load(campaign)
        block_rows, trend_rows, comparison_rows = analyze(points, list_entries)
    except ValueError as error:
        print(f"analyze_scaling: {error}", file=sys.stderr)
        return 1
    output.mkdir(parents=True, exist_ok=True)
    write_csv(output / "blocks.csv", block_rows)
    write_csv(output / "trends.csv", trend_rows)
    write_csv(output / "comparisons.csv", comparison_rows)
    text = report(block_rows, trend_rows, comparison_rows, campaign)
    (output / "report.txt").write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    print(f"written: {output}/{{blocks.csv,trends.csv,comparisons.csv,report.txt}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
