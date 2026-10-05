#!/usr/bin/env python3
"""Tests for tools/analyze_scaling.py.

The reference quantiles and tail probabilities are standard table values, not
outputs of the module under test; the analysis of variance is checked against a
case small enough to compute by hand; the `pairs` interval is checked against
tools/stats.awk, which the harness uses for the same interval.
"""

import csv
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import analyze_scaling as tool  # noqa: E402

TARGETS = ("prover", "verifier", "raw_agg", "mldsa_raw_agg")
COLUMNS = ("n", "t", "list_entries", "sweep", "sweep_direction", "sweep_position", "target", "run", "t_start",
           "prove_med_ms", "prove_cpu_med_ms", "decode_verify_med_ms", "decode_verify_cpu_med_ms")


def campaign(folder: Path, values, sizes=(5, 10), sweeps=2, runs=4, drop=None) -> Path:
    """Write a synthetic all-runs.csv. `values(n, sweep, target, run)` gives the elapsed ms."""
    with (folder / "all-runs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for n in sizes:
            for sweep in range(1, sweeps + 1):
                direction = "ascending" if sweep % 2 else "descending"
                for run in range(1, runs + 1):
                    for position, target in enumerate(TARGETS):
                        if drop == (n, sweep, target, run):
                            continue
                        elapsed = values(n, sweep, target, run)
                        start = 1_000_000 * sweep + 100 * run + position
                        prove = (elapsed, 8 * elapsed) if target == "prover" else ("", "")
                        verify = ("", "") if target == "prover" else (elapsed, elapsed)
                        writer.writerow([n, 2 * n // 3 + 1, 1000, sweep, direction, 1, target, run, start,
                                         *(f"{v:.6f}" if v != "" else "" for v in (*prove, *verify))])
    return folder


def base(n, sweep, target, run):
    """Raw verifier clearly slower than the SNARK verifier at every N, small run-to-run noise."""
    level = {"prover": 500.0, "verifier": 100.0, "raw_agg": 100.0 + 2.0 * n, "mldsa_raw_agg": 100.0 + 3.0 * n}[target]
    return level + 0.1 * ((run * 7 + sweep * 3 + len(target)) % 5)


class Distributions(unittest.TestCase):
    def test_student_quantiles_match_the_tables(self):
        for df, expected in ((1, 12.706205), (2, 4.302653), (10, 2.228139), (30, 2.042272), (47, 2.011741)):
            self.assertAlmostEqual(tool.t_quantile(0.95, df), expected, places=5)
        self.assertAlmostEqual(tool.t_quantile(0.99, 10), 3.169273, places=5)

    def test_tail_probabilities_match_the_tables(self):
        self.assertAlmostEqual(tool.t_two_sided_p(2.228139, 10), 0.05, places=6)
        self.assertAlmostEqual(tool.f_upper_p(4.964603, 1, 10), 0.05, places=6)
        self.assertAlmostEqual(tool.f_upper_p(3.885294, 2, 12), 0.05, places=6)
        self.assertEqual(tool.t_two_sided_p(0.0, 7), 1.0)
        self.assertEqual(tool.f_upper_p(0.0, 2, 9), 1.0)

    def test_f_with_one_numerator_degree_is_t_squared(self):
        for statistic, df in ((0.3, 3), (1.7, 11), (4.2, 46)):
            self.assertAlmostEqual(tool.f_upper_p(statistic * statistic, 1, df), tool.t_two_sided_p(statistic, df), places=12)


class Estimates(unittest.TestCase):
    def test_analysis_of_variance_by_hand(self):
        result = tool.blocks([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])
        self.assertAlmostEqual(result["mean"], 3.5)
        self.assertEqual(result["session_means"], [2.0, 5.0])
        self.assertAlmostEqual(result["ms_between"], 13.5)
        self.assertAlmostEqual(result["ms_within"], 1.0)
        self.assertAlmostEqual(result["f"], 13.5)
        self.assertAlmostEqual(result["icc"], 12.5 / 15.5)
        self.assertAlmostEqual(result["pairs"][0], math.sqrt(17.5 / 5 / 6))
        self.assertEqual(result["pairs"][1], 5)
        self.assertAlmostEqual(result["within_sessions"][0], math.sqrt(1.0 / 6))
        self.assertEqual(result["within_sessions"][1], 4)
        self.assertAlmostEqual(result["sessions_unit"][0], 1.5)
        self.assertEqual(result["sessions_unit"][1], 1)

    def test_one_session_has_no_session_level_interval(self):
        result = tool.blocks([[1.0, 2.0, 4.0]])
        self.assertEqual(result["sessions_unit"], (None, 0))
        self.assertIsNone(result["f"])
        self.assertIsNone(result["icc"])
        self.assertIsNone(tool.interval(1.0, 1.0, 0))

    def test_unbalanced_sessions_are_refused(self):
        with self.assertRaises(ValueError):
            tool.blocks([[1.0, 2.0], [3.0]])

    def test_the_pairs_interval_is_the_harness_interval(self):
        values = [3.1, 2.7, 3.9, 3.3, 2.2, 4.0, 3.6, 2.9]
        result = tool.blocks([values[:4], values[4:]])
        se, df = result["pairs"]
        low, high = tool.interval(result["mean"], se, df)
        awk = subprocess.run(["awk", "-f", str(TOOLS / "stats.awk")], text=True, capture_output=True, check=True,
                             input="\n".join(str(v) for v in sorted(values)) + "\n").stdout.split()
        self.assertAlmostEqual(result["mean"], float(awk[6]), places=5)
        self.assertAlmostEqual((high - low) / 2, float(awk[9]), places=5)

    def test_trend_recovers_a_line_and_needs_three_points(self):
        fitted = tool.trend([10.0 + 0.5 * i for i in range(1, 9)])
        self.assertAlmostEqual(fitted["slope"], 0.5)
        self.assertAlmostEqual(fitted["se"], 0.0)
        self.assertIsNone(tool.trend([1.0, 2.0])["slope"])
        alternating = tool.trend([1.0, -1.0] * 6)
        self.assertLess(alternating["lag1"], -0.8)

    def test_holm_adjustment(self):
        adjusted = tool.holm([0.01, 0.04, 0.03, None])
        self.assertAlmostEqual(adjusted[0], 0.03)
        self.assertAlmostEqual(adjusted[1], 0.06)
        self.assertAlmostEqual(adjusted[2], 0.06)
        self.assertIsNone(adjusted[3])
        self.assertEqual(tool.holm([0.5, 0.9]), [1.0, 1.0])

    def test_sign_of_an_interval(self):
        self.assertEqual(tool.sign((0.1, 2.0)), "a_slower")
        self.assertEqual(tool.sign((-2.0, -0.1)), "b_slower")
        self.assertEqual(tool.sign((-0.1, 2.0)), "not_confirmed")
        self.assertEqual(tool.sign(None), "no_interval")


class Campaigns(unittest.TestCase):
    def analyze(self, folder: Path):
        points, list_entries = tool.load(folder)
        return tool.analyze(points, list_entries)

    def test_a_consistent_difference_is_confirmed_under_every_reading(self):
        with tempfile.TemporaryDirectory() as scratch:
            _, _, comparisons = self.analyze(campaign(Path(scratch), base))
        self.assertEqual(len(comparisons), 2 * 3 * 2)
        for row in comparisons:
            self.assertEqual(row["family_size"], 12)
            if row["b"] == "snark":
                for key in ("pairs_sign", "within_sessions_sign", "sessions_sign",
                            "pairs_simultaneous_sign", "sessions_simultaneous_sign"):
                    self.assertEqual(row[key], "a_slower", (row["n"], row["a"], key))
            # a simultaneous interval contains the individual one
            self.assertLessEqual(row["pairs_simultaneous_ci95_low"], row["pairs_ci95_low"])
            self.assertGreaterEqual(row["pairs_simultaneous_ci95_high"], row["pairs_ci95_high"])
            self.assertGreaterEqual(row["pairs_p_holm"], row["pairs_p"])

    def test_a_difference_that_varies_between_sessions_is_not_confirmed_at_session_level(self):
        def shifting(n, sweep, target, run):
            # raw is 6 ms slower in the first session and 1 ms slower in the second
            if target == "raw_agg":
                return 100.0 + (6.0 if sweep == 1 else 1.0) + 0.05 * (run % 2)
            return 100.0 if target != "prover" else 500.0
        with tempfile.TemporaryDirectory() as scratch:
            blocks, _, comparisons = self.analyze(campaign(Path(scratch), shifting, sizes=(5,)))
        row = next(r for r in comparisons if r["a"] == "xmss_raw" and r["b"] == "snark" and r["clock"] == "elapsed")
        self.assertEqual(row["pairs_sign"], "a_slower")
        self.assertEqual(row["sessions_sign"], "not_confirmed")
        self.assertLess(row["f_p"], 0.001)
        self.assertGreater(row["icc"], 0.9)
        raw = next(r for r in blocks if r["role"] == "xmss_raw_verifier" and r["clock"] == "elapsed")
        self.assertAlmostEqual(raw["session_spread_pct"], 100.0 * 5.0 / raw["mean_ms"], places=2)

    def test_a_drift_inside_a_session_is_reported(self):
        def drifting(n, sweep, target, run):
            noise = 0.02 * ((run * 5) % 3)
            return (100.0 + 2.0 * run + noise) if target == "verifier" else (500.0 if target == "prover" else 300.0 + noise)
        with tempfile.TemporaryDirectory() as scratch:
            _, trends, _ = self.analyze(campaign(Path(scratch), drifting, sizes=(5,), runs=8))
        snark = [r for r in trends if r["role"] == "snark_verifier" and r["clock"] == "elapsed"]
        self.assertEqual(len(snark), 2)
        for row in snark:
            self.assertEqual(row["drift"], "rising")
            self.assertAlmostEqual(row["slope_ms_per_run"], 2.0, places=1)
        flat = [r for r in trends if r["role"] == "xmss_raw_verifier" and r["clock"] == "elapsed"]
        self.assertTrue(all(row["drift"] == "not_confirmed" for row in flat))

    def test_one_sweep_gives_no_session_level_interval(self):
        with tempfile.TemporaryDirectory() as scratch:
            _, _, comparisons = self.analyze(campaign(Path(scratch), base, sweeps=1))
        for row in comparisons:
            self.assertEqual(row["sessions_sign"], "no_interval")
            self.assertIsNone(row["sessions_p_holm"])
            self.assertNotEqual(row["pairs_sign"], "no_interval")

    def test_the_command_writes_its_files_and_refuses_damaged_input(self):
        script = str(TOOLS / "analyze_scaling.py")
        with tempfile.TemporaryDirectory() as scratch:
            folder = campaign(Path(scratch), base)
            done = subprocess.run([sys.executable, script, str(folder)], text=True, capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            for name in ("blocks.csv", "trends.csv", "comparisons.csv", "report.txt"):
                self.assertTrue((folder / "analysis" / name).is_file(), name)
            with (folder / "analysis" / "comparisons.csv").open(newline="", encoding="utf-8") as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 12)
            self.assertIn("FIRST OBSERVED POINTS", done.stdout)
        with tempfile.TemporaryDirectory() as scratch:
            folder = campaign(Path(scratch), base, drop=(10, 2, "raw_agg", 3))
            done = subprocess.run([sys.executable, script, str(folder)], text=True, capture_output=True)
            self.assertEqual(done.returncode, 1)
            self.assertIn("different runs", done.stderr)
            self.assertFalse((folder / "analysis").exists())
        with tempfile.TemporaryDirectory() as scratch:
            done = subprocess.run([sys.executable, script, scratch], text=True, capture_output=True)
            self.assertEqual(done.returncode, 1)
            self.assertIn("all-runs.csv", done.stderr)


if __name__ == "__main__":
    unittest.main()
