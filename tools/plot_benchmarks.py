#!/usr/bin/env python3
"""Render benchmark CSVs as standalone SVG figures and an auditable Markdown table.

No third-party packages are required. The input directory may contain either a
single fixed-committee benchmark (summary.csv) or a scaling campaign
(scaling.csv, manifest.csv and signer.csv). Plotting never changes source CSVs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import sys
from pathlib import Path
from xml.sax.saxutils import escape


COLORS = {
    "verifier": "#2369a8",
    "raw_agg": "#c65a28",
    "mldsa_raw_agg": "#29815f",
    "prover": "#7355a6",
    "signer": "#a14d79",
    "mldsa_signer": "#647c31",
}
NAMES = {
    "verifier": "XMSS / SNARK verifier",
    "raw_agg": "XMSS raw verifier",
    "mldsa_raw_agg": "ML-DSA raw verifier",
    "prover": "XMSS / SNARK prover",
    "signer": "XMSS signer",
    "mldsa_signer": "ML-DSA signer",
}


def rows(path: Path, required: tuple[str, ...]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        missing = set(required) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        return list(reader)


def value(row: dict[str, str], key: str, *, positive: bool = False) -> float | None:
    raw = row.get(key, "")
    if raw is None or raw == "":
        return None
    try:
        number = float(raw)
    except ValueError as exc:
        raise ValueError(f"invalid {key}={raw!r}") from exc
    if not math.isfinite(number) or (positive and number <= 0):
        raise ValueError(f"invalid {key}={raw!r}")
    return number


def shown(number: float | None, unit: str = "") -> str:
    if number is None:
        return "—"
    if unit in ("bytes", "MB", "count"):
        return f"{number:,.0f}"
    if abs(number) >= 100:
        return f"{number:,.1f}"
    if abs(number) >= 1:
        return f"{number:,.2f}"
    return f"{number:,.3f}"


def tag(name: str, attrs: str = "") -> str:
    return f"<{name}{(' ' + attrs) if attrs else ''}>"


def svg_text(x: float, y: float, content: str, size: int = 15, **attrs: str) -> str:
    extra = " ".join(f'{("class" if key == "class_" else key.replace("_", "-"))}="{escape(val)}"' for key, val in attrs.items())
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" {extra}>{escape(content)}</text>'


def write_svg(path: Path, width: int, height: int, elements: list[str]) -> None:
    body = "\n".join(elements)
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">\n'
        '<style>text{font-family:DejaVu Sans,Arial,sans-serif;fill:#202a34}'
        '.muted{fill:#57636e}.grid{stroke:#dce3e8;stroke-width:1}'
        '.axis{stroke:#53616d;stroke-width:1.4}</style>\n'
        f'{body}\n</svg>\n',
        encoding="utf-8",
    )


def empty_plot(path: Path, title: str) -> None:
    write_svg(path, 900, 160, [
        svg_text(28, 42, title, 22, font_weight="bold"),
        svg_text(28, 86, "No complete measured values are available for this figure.", 16),
    ])


def decade_bounds(numbers: list[float]) -> tuple[float, float]:
    lower = 10 ** math.floor(math.log10(min(numbers)))
    upper = 10 ** math.ceil(math.log10(max(numbers)))
    if lower == upper:
        upper *= 10
    return lower, upper


def dot_plot(
    path: Path, title: str, subtitle: str, unit: str,
    points: list[tuple[str, float, float, float, int, str]],
) -> None:
    """Horizontal logarithmic dot plot; quartile whiskers are between-run only."""
    if not points:
        empty_plot(path, title)
        return
    values = [x for _, median, q1, q3, _, _ in points for x in (median, q1, q3)]
    lower, upper = decade_bounds(values)
    width, height = 1110, 175 + 52 * len(points)
    left, right = 350, 880

    def x_pos(number: float) -> float:
        return left + (math.log10(number) - math.log10(lower)) / (
            math.log10(upper) - math.log10(lower)
        ) * (right - left)

    out = [svg_text(28, 37, title, 22, font_weight="bold"),
           svg_text(28, 62, subtitle, 13, class_="muted")]
    power = math.floor(math.log10(lower))
    while 10 ** power <= upper:
        tick = 10 ** power
        x = x_pos(tick)
        out.append(f'<line x1="{x:.1f}" y1="83" x2="{x:.1f}" y2="{height-57}" class="grid"/>')
        out.append(svg_text(x, height - 36, shown(tick, unit), 12, text_anchor="middle"))
        power += 1
    for index, (label, median, q1, q3, n, color) in enumerate(points):
        y = 105 + index * 52
        out.append(svg_text(28, y + 5, label, 15))
        if n > 1:
            out.append(f'<line x1="{x_pos(q1):.1f}" y1="{y}" x2="{x_pos(q3):.1f}" '
                       f'y2="{y}" stroke="{color}" stroke-width="5" stroke-linecap="round"/>')
        out.append(f'<circle cx="{x_pos(median):.1f}" cy="{y}" r="7" fill="{color}"/>')
        out.append(svg_text(905, y + 5, f'{shown(median, unit)} {unit}  (n={n})', 14))
    out.append(svg_text(left, height - 13, "Logarithmic axis · dots: medians · lines: Q1–Q3 across runs", 12, class_="muted"))
    write_svg(path, width, height, out)


def line_plot(
    path: Path, title: str, subtitle: str, unit: str,
    data: list[dict[str, str]], specs: list[tuple[str, str, str]],
) -> None:
    """Measured committee sizes only; dashed connectors guide the eye."""
    plotted = [(name, key, color, [(int(row["n"]), value(row, key, positive=True))
                                  for row in data if value(row, key, positive=True) is not None])
               for name, key, color in specs]
    plotted = [(name, key, color, pts) for name, key, color, pts in plotted if pts]
    if not plotted:
        empty_plot(path, title)
        return
    all_y = [y for _, _, _, pts in plotted for _, y in pts]
    ymin, ymax = decade_bounds(all_y)
    ns = sorted({int(row["n"]) for row in data})
    xmin = math.log10(min(ns)) - 0.15
    xmax = math.log10(max(ns)) + 0.15
    if xmin == xmax:
        xmin -= 0.5
        xmax += 0.5
    width, height = 1120, 620
    left, right, top, bottom = 105, 815, 100, 510

    def px(n: int) -> float:
        return left + (math.log10(n) - xmin) / (xmax - xmin) * (right - left)

    def py(y: float) -> float:
        return bottom - (math.log10(y) - math.log10(ymin)) / (
            math.log10(ymax) - math.log10(ymin)
        ) * (bottom - top)

    out = [svg_text(28, 38, title, 22, font_weight="bold"),
           svg_text(28, 64, subtitle, 13, class_="muted")]
    power = math.floor(math.log10(ymin))
    while 10 ** power <= ymax:
        tick = 10 ** power
        y = py(tick)
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" class="grid"/>')
        out.append(svg_text(left - 15, y + 4, shown(tick, unit), 12, text_anchor="end"))
        power += 1
    by_n = {int(row["n"]): row for row in data}
    for n in ns:
        x = px(n)
        out.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{bottom}" class="grid"/>')
        out.append(svg_text(x, bottom + 25, f'N={n}', 13, text_anchor="middle"))
        out.append(svg_text(x, bottom + 43, f't={by_n[n]["t"]}', 12, text_anchor="middle", class_="muted"))
    out.append(f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" class="axis"/>')
    for index, (name, _key, color, points) in enumerate(plotted):
        points.sort()
        if len(points) > 1:
            coords = " ".join(f'{px(n):.1f},{py(y):.1f}' for n, y in points)
            out.append(f'<polyline points="{coords}" fill="none" stroke="{color}" '
                       'stroke-width="2" stroke-dasharray="5 4"/>')
        for n, y in points:
            out.append(f'<circle cx="{px(n):.1f}" cy="{py(y):.1f}" r="6" fill="{color}">'
                       f'<title>N={n}: {shown(y, unit)} {escape(unit)}</title></circle>')
        legend_y = 145 + index * 38
        out.append(f'<circle cx="850" cy="{legend_y-5}" r="6" fill="{color}"/>')
        out.append(svg_text(867, legend_y, name, 14))
    out.append(svg_text(left, height - 17, "Logarithmic axes · markers: measured points · dashed lines: visual guide only", 12, class_="muted"))
    write_svg(path, width, height, out)


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixed_metadata(folder: Path) -> dict[str, str]:
    report = folder / "summary.txt"
    if not report.exists():
        return {}
    result = {}
    for line in report.read_text(encoding="utf-8").splitlines()[:35]:
        key, separator, detail = line.partition(":")
        key = key.strip()
        if separator and key in ("generated", "host", "governor", "threads", "committee"):
            result[key] = detail.strip()
    return result


def fixed_campaign(folder: Path, output: Path) -> list[Path]:
    source = folder / "summary.csv"
    data = rows(source, ("target", "metric", "unit", "n", "q1", "median", "q3"))
    metadata = fixed_metadata(folder)
    indexed: dict[tuple[str, str], dict[str, str]] = {}
    for row in data:
        key = (row["target"], row["metric"])
        if key in indexed:
            raise ValueError(f"{source}: duplicate {key}")
        if value(row, "n", positive=True) is None:
            raise ValueError(f"{source}: missing n for {key}")
        indexed[key] = row

    figures: list[Path] = []

    def chart(filename: str, title: str, subtitle: str, unit: str,
              selection: list[tuple[str, str, str]]) -> None:
        points = []
        for target, metric, label in selection:
            row = indexed.get((target, metric))
            if row is None:
                continue
            median = value(row, "median", positive=True)
            q1 = value(row, "q1", positive=True)
            q3 = value(row, "q3", positive=True)
            if median is None or q1 is None or q3 is None:
                continue
            points.append((label, median, q1, q3, int(row["n"]), COLORS[target]))
        destination = output / filename
        labelled_title = f"{title} · {metadata['committee']}" if metadata.get("committee") else title
        dot_plot(destination, labelled_title, subtitle, unit, points)
        figures.append(destination)

    chart("verification.svg", "Record decode + verification", "Per-update median across independent process runs", "ms", [
        ("verifier", "decode_verify_per_item", NAMES["verifier"]),
        ("raw_agg", "decode_verify_per_item", NAMES["raw_agg"]),
        ("mldsa_raw_agg", "decode_verify_per_item", NAMES["mldsa_raw_agg"]),
    ])
    chart("verification_phases.svg", "Receiver decode and verify phases", "Per-update medians; end-to-end time is measured contiguously", "ms", [
        ("verifier", "decode_per_item", "SNARK decode"),
        ("verifier", "verify_per_item", "SNARK verify-only"),
        ("verifier", "decode_verify_per_item", "SNARK end-to-end"),
        ("raw_agg", "decode_per_item", "XMSS raw decode"),
        ("raw_agg", "verify_per_item", "XMSS raw verify-only"),
        ("raw_agg", "decode_verify_per_item", "XMSS raw end-to-end"),
        ("mldsa_raw_agg", "decode_per_item", "ML-DSA raw decode"),
        ("mldsa_raw_agg", "verify_per_item", "ML-DSA raw verify-only"),
        ("mldsa_raw_agg", "decode_verify_per_item", "ML-DSA raw end-to-end"),
    ])
    chart("record_sizes.svg", "Published record size", "Entire serialized records, including signatures and framing", "bytes", [
        ("prover", "record_size", "XMSS / SNARK record"),
        ("raw_agg", "record_size", "XMSS raw record"),
        ("mldsa_raw_agg", "record_size", "ML-DSA raw record"),
    ])
    chart("signature_sizes.svg", "Individual signature size", "One signature; not a complete published record", "bytes", [
        ("signer", "signature_size", "XMSS signature"),
        ("mldsa_signer", "signature_size", "ML-DSA-65 signature"),
    ])
    chart("signing.svg", "Single-member signing cost", "XMSS protocol includes durable slot burn; ML-DSA is crypto-only", "ms", [
        ("signer", "sign_protocol_per_item", "XMSS protocol sign"),
        ("signer", "slot_burn_per_item", "XMSS slot burn"),
        ("signer", "sign_crypto_per_item", "XMSS crypto sign"),
        ("mldsa_signer", "sign_crypto_per_item", "ML-DSA crypto sign"),
    ])
    chart("peak_memory.svg", "Peak process RSS", "Kernel ru_maxrss; integer MiB", "MB", [
        ("signer", "peak_rss_kernel", "XMSS signer"),
        ("mldsa_signer", "peak_rss_kernel", "ML-DSA signer"),
        ("prover", "peak_rss_kernel", "XMSS / SNARK prover"),
        ("verifier", "peak_rss_kernel", "XMSS / SNARK verifier"),
        ("raw_agg", "peak_rss_kernel", "XMSS raw verifier"),
        ("mldsa_raw_agg", "peak_rss_kernel", "ML-DSA raw verifier"),
    ])
    lines = ["# Fixed-committee benchmark", "", f"Source: `{source.name}` (SHA-256 `{fingerprint(source)}`).", "",
             "Each row summarizes per-process run values. For per-update metrics, each run contributes its median.",
             "Q1–Q3 describes spread between runs; with n=1 there is no uncertainty estimate.",
             "XMSS protocol signing includes durable slot reservation. ML-DSA signing here measures cryptography only.",
             "Setup and proving belong to the aggregator or verifier role and are not added to signing or receiver cost.", "",
             "| Target | Metric | n | Median | Q1–Q3 | Unit |", "| --- | --- | ---: | ---: | ---: | --- |"]
    if metadata:
        lines[3:3] = ["Campaign: " + "; ".join(f"{key}={metadata[key]}" for key in
                                          ("generated", "host", "governor", "threads", "committee")
                                          if key in metadata), ""]
    for row in data:
        unit = row["unit"]
        median = value(row, "median")
        q1 = value(row, "q1")
        q3 = value(row, "q3")
        spread = f"{shown(q1, unit)}–{shown(q3, unit)}" if int(row["n"]) > 1 else "—"
        lines.append(f'| {NAMES.get(row["target"], row["target"])} | `{row["metric"]}` | {row["n"]} | '
                     f'{shown(median, unit)} | {spread} | {unit} |')
    lines.extend(["", "Figures: " + ", ".join(f"[{path.name}]({path.name})" for path in figures) + ".", ""])
    (output / "overview.md").write_text("\n".join(lines), encoding="utf-8")
    return figures


def scaling_campaign(folder: Path, output: Path) -> list[Path]:
    source = folder / "scaling.csv"
    data = rows(source, ("n", "t", "observations", "prove_ms", "snark_decode_verify_ms",
                         "raw_decode_verify_ms", "snark_record_bytes", "raw_record_bytes",
                         "verify_advantage_confirmed", "break_even_median"))
    seen = set()
    for row in data:
        n = value(row, "n", positive=True)
        t = value(row, "t", positive=True)
        obs = value(row, "observations", positive=True)
        if n is None or t is None or obs is None or int(n) != n or int(t) != t or int(obs) != obs or t > n:
            raise ValueError(f"{source}: invalid N, t or observation count")
        if (n, t) in seen:
            raise ValueError(f"{source}: duplicate point N={int(n)}, t={int(t)}")
        seen.add((n, t))
        required_positive = ("prove_ms", "snark_decode_verify_ms", "raw_decode_verify_ms",
                             "mldsa_decode_verify_ms", "snark_record_bytes", "raw_record_bytes",
                             "mldsa_record_bytes", "prover_peak_mb", "snark_verifier_peak_mb",
                             "raw_verifier_peak_mb", "mldsa_verifier_peak_mb")
        for field in required_positive:
            if value(row, field, positive=True) is None:
                raise ValueError(f"{source}: missing {field} at N={int(n)}, t={int(t)}")
        if row["verify_advantage_confirmed"] not in ("0", "1"):
            raise ValueError(f"{source}: invalid verify_advantage_confirmed at N={int(n)}, t={int(t)}")
    manifest = folder / "manifest.csv"
    manifest_entries = rows(manifest, ("n", "t", "status", "reason")) if manifest.exists() else []
    manifest_status = {(int(entry["n"]), int(entry["t"])): entry["status"]
                       for entry in manifest_entries}
    for row in data:
        if manifest_entries and manifest_status.get((int(row["n"]), int(row["t"]))) != "complete":
            raise ValueError(f"{source}: N={row['n']}, t={row['t']} is not complete in manifest.csv")
    for entry in manifest_entries:
        if entry["status"] == "complete" and (int(entry["n"]), int(entry["t"])) not in seen:
            raise ValueError(f"{source}: manifest marks N={entry['n']}, t={entry['t']} complete but scaling.csv has no row")
    data.sort(key=lambda row: int(row["n"]))
    figures: list[Path] = []

    def chart(filename: str, title: str, subtitle: str, unit: str,
              specs: list[tuple[str, str, str]]) -> None:
        destination = output / filename
        line_plot(destination, title, subtitle, unit, data, specs)
        figures.append(destination)

    chart("verification_scaling.svg", "Receiver cost by committee size", "End-to-end record decode + verify; medians of run medians", "ms", [
        ("XMSS / SNARK", "snark_decode_verify_ms", COLORS["verifier"]),
        ("XMSS raw", "raw_decode_verify_ms", COLORS["raw_agg"]),
        ("ML-DSA raw", "mldsa_decode_verify_ms", COLORS["mldsa_raw_agg"]),
    ])
    chart("record_scaling.svg", "Published record size by committee size", "Complete serialized record bytes", "bytes", [
        ("XMSS / SNARK", "snark_record_bytes", COLORS["verifier"]),
        ("XMSS raw", "raw_record_bytes", COLORS["raw_agg"]),
        ("ML-DSA raw", "mldsa_record_bytes", COLORS["mldsa_raw_agg"]),
    ])
    chart("prover_scaling.svg", "XMSS / SNARK proving cost", "One aggregator; per-update median, excludes fixture signing", "ms", [
        ("Prove", "prove_ms", COLORS["prover"]),
    ])
    chart("memory_scaling.svg", "Peak process RSS by role", "Kernel ru_maxrss, integer MiB", "MB", [
        ("Prover", "prover_peak_mb", COLORS["prover"]),
        ("SNARK verifier", "snark_verifier_peak_mb", COLORS["verifier"]),
        ("XMSS raw verifier", "raw_verifier_peak_mb", COLORS["raw_agg"]),
        ("ML-DSA raw verifier", "mldsa_verifier_peak_mb", COLORS["mldsa_raw_agg"]),
    ])
    confirmed = [row for row in data if row["verify_advantage_confirmed"] == "1"
                 and value(row, "break_even_median", positive=True) is not None]
    destination = output / "break_even.svg"
    line_plot(destination, "Observed XMSS / SNARK break-even", "Independent receiver checks needed to repay one proof; confirmed points only", "count", confirmed, [
        ("Break-even", "break_even_median", COLORS["prover"]),
    ])
    figures.append(destination)

    lines = ["# Committee scaling benchmark", "", f"Source: `{source.name}` (SHA-256 `{fingerprint(source)}`).", "",
             "Only completed measured points in scaling.csv are plotted. Each point is a median of process-run medians.",
             "Log axes show orders of magnitude; dashed connectors are visual guides, not interpolated measurements.",
             "ML-DSA is a separate raw signature construction. XMSS raw and XMSS/SNARK share the same signer cost.",
             "The paired time advantage uses the campaign's 95% interval; it is not an across-host claim.", ""]
    if data:
        def first(predicate: object) -> str:
            selected = next((row for row in data if predicate(row)), None)
            return f'N={selected["n"]}, t={selected["t"]}' if selected else "not observed in completed grid"

        lines.extend(["## First observed points", "",
                      f'- Smaller XMSS/SNARK record: {first(lambda row: value(row, "snark_record_bytes") < value(row, "raw_record_bytes"))}.',
                      f'- Confirmed faster XMSS/SNARK verification: {first(lambda row: row["verify_advantage_confirmed"] == "1")}.',
                      f'- Both conditions: {first(lambda row: row["verify_advantage_confirmed"] == "1" and value(row, "snark_record_bytes") < value(row, "raw_record_bytes"))}.',
                      "", "## Verification", "",
                      "| N | t | Runs | SNARK e2e ms | XMSS raw e2e ms | ML-DSA raw e2e ms | Raw−SNARK mean ms [95% CI] | Confirmed | Break-even checks |",
                      "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: | ---: |"])
        for row in data:
            delta = shown(value(row, "verify_delta_mean_ms"), "ms")
            lo = shown(value(row, "verify_delta_ci95_low"), "ms")
            hi = shown(value(row, "verify_delta_ci95_high"), "ms")
            lines.append(f'| {row["n"]} | {row["t"]} | {row["observations"]} | '
                         f'{shown(value(row, "snark_decode_verify_ms"), "ms")} | '
                         f'{shown(value(row, "raw_decode_verify_ms"), "ms")} | '
                         f'{shown(value(row, "mldsa_decode_verify_ms"), "ms")} | '
                         f'{delta} [{lo}, {hi}] | '
                         f'{"yes" if row["verify_advantage_confirmed"] == "1" else "no"} | '
                         f'{shown(value(row, "break_even_median"), "count")} |')
        lines.extend(["", "## Receiver phases (ms per update)", "",
                      "| N | t | SNARK decode | SNARK verify-only | XMSS raw decode | XMSS raw verify-only | ML-DSA raw decode | ML-DSA raw verify-only |",
                      "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
        for row in data:
            phase_fields = ("snark_decode_ms", "snark_verify_only_ms", "raw_decode_ms",
                            "raw_verify_only_ms", "mldsa_decode_ms", "mldsa_verify_ms")
            phase_values = [shown(value(row, field), "ms") for field in phase_fields]
            lines.append(f'| {row["n"]} | {row["t"]} | ' + " | ".join(phase_values) + " |")
        lines.extend(["", "## Derived ratios", "",
                      "| N | t | Raw/SNARK verification speedup median [Q1, Q3] | Break-even checks median [Q1, Q3] |",
                      "| ---: | ---: | ---: | ---: |"])
        for row in data:
            speed = ", ".join(shown(value(row, field)) for field in
                              ("verify_speedup_median", "verify_speedup_q1", "verify_speedup_q3"))
            bounds = ("break_even_median", "break_even_q1", "break_even_q3")
            breakeven = ", ".join(shown(value(row, field), "count") for field in bounds)
            lines.append(f'| {row["n"]} | {row["t"]} | {speed} | {breakeven} |')
        lines.extend(["", "## Record size and resources", "",
                      "| N | t | SNARK B | XMSS raw B | ML-DSA raw B | XMSS wire reduction % | Prove ms | Prover peak MiB | SNARK verifier peak MiB | XMSS raw peak MiB | ML-DSA raw peak MiB |",
                      "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
        for row in data:
            fields = ("snark_record_bytes", "raw_record_bytes", "mldsa_record_bytes",
                      "wire_reduction_pct", "prove_ms", "prover_peak_mb", "snark_verifier_peak_mb",
                      "raw_verifier_peak_mb", "mldsa_verifier_peak_mb")
            units = ("bytes", "bytes", "bytes", "%", "ms", "MB", "MB", "MB", "MB")
            values = [shown(value(row, field), unit) for field, unit in zip(fields, units)]
            lines.append(f'| {row["n"]} | {row["t"]} | ' + " | ".join(values) + " |")
    else:
        lines.extend(["No complete measured scaling points are present. Figures mark these metrics unavailable.", ""])

    manifest = folder / "manifest.csv"
    if manifest.exists():
        entries = rows(manifest, ("n", "t", "status", "reason"))
        lines.extend(["", "## All requested points", "",
                      "| N | t | Status | Reason |", "| ---: | ---: | --- | --- |"])
        for row in entries:
            reason = row["reason"].replace("|", "\\|").replace("\n", " ")
            lines.append(f'| {row["n"]} | {row["t"]} | {row["status"]} | {reason} |')
    signer = folder / "signer.csv"
    if signer.exists():
        signer_rows = rows(signer, ("target", "metric", "unit", "n", "median"))
        lines.extend(["", "## Single-member signers (measured once for the sweep)", "",
                      "| Target | Metric | Runs | Median | Unit |", "| --- | --- | ---: | ---: | --- |"])
        for row in signer_rows:
            lines.append(f'| {NAMES.get(row["target"], row["target"])} | `{row["metric"]}` | '
                         f'{row["n"]} | {shown(value(row, "median"), row["unit"])} | {row["unit"]} |')
    lines.extend(["", "Figures: " + (", ".join(f"[{path.name}]({path.name})" for path in figures) if figures else "none") + ".", ""])
    (output / "overview.md").write_text("\n".join(lines), encoding="utf-8")
    return figures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path, help="benchmark.sh or committee-scaling-benchmark.sh output directory")
    parser.add_argument("--outdir", type=Path, help="figure directory (default: CAMPAIGN/plots)")
    args = parser.parse_args()
    folder = args.campaign.resolve()
    output = (args.outdir or folder / "plots").resolve()
    if not folder.is_dir():
        parser.error(f"not a directory: {folder}")
    scaling = (folder / "scaling.csv").is_file()
    fixed = (folder / "summary.csv").is_file()
    if not scaling and not fixed:
        parser.error(f"no scaling.csv or summary.csv in {folder}")
    output.mkdir(parents=True, exist_ok=True)
    try:
        figures = scaling_campaign(folder, output) if scaling else fixed_campaign(folder, output)
    except (OSError, ValueError, OverflowError) as exc:
        print(f"plot_benchmarks: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {output / 'overview.md'} and {len(figures)} SVG figure(s) to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
