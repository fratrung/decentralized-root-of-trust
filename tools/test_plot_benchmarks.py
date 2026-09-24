#!/usr/bin/env python3
"""Small contract checks for the CSV plotting tool (no external packages)."""

import csv
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


TOOL = Path(__file__).with_name("plot_benchmarks.py")


def write_csv(path, fields, records):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


class PlotBenchmarksTest(unittest.TestCase):
    def run_plot(self, folder):
        return subprocess.run(
            [sys.executable, "-B", str(TOOL), str(folder)],
            capture_output=True, text=True, check=False,
        )

    def test_fixed_campaign_marks_single_run_without_uncertainty(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fields = ("target", "metric", "unit", "n", "q1", "median", "q3")
            write_csv(folder / "summary.csv", fields, [
                {"target": "raw_agg", "metric": "decode_verify_per_item",
                 "unit": "ms", "n": "1", "q1": "0.25", "median": "0.25", "q3": "0.25"},
            ])
            result = self.run_plot(folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (folder / "plots/overview.md").read_text(encoding="utf-8")
            self.assertIn("n=1 there is no uncertainty estimate", text)
            self.assertIn("| 1 | 0.250 | — | ms |", text)
            for figure in (folder / "plots").glob("*.svg"):
                ET.parse(figure)
            self.assertEqual(len(list((folder / "plots").glob("*.svg"))), 6)

    def test_scaling_campaign_excludes_unmeasured_points(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fields = ("n", "t", "observations", "prove_ms",
                      "snark_decode_verify_ms", "raw_decode_verify_ms",
                      "mldsa_decode_verify_ms", "snark_record_bytes",
                      "raw_record_bytes", "mldsa_record_bytes",
                      "prover_peak_mb", "snark_verifier_peak_mb",
                      "raw_verifier_peak_mb", "mldsa_verifier_peak_mb",
                      "verify_advantage_confirmed", "break_even_median",
                      "verify_delta_mean_ms", "verify_delta_ci95_low",
                      "verify_delta_ci95_high", "wire_reduction_pct")
            base = dict.fromkeys(fields, "")
            base.update(t="4", observations="48", prove_ms="500",
                        snark_decode_verify_ms="2", raw_decode_verify_ms="1",
                        mldsa_decode_verify_ms="1.5", snark_record_bytes="4000",
                        raw_record_bytes="5000", mldsa_record_bytes="9000",
                        prover_peak_mb="700", snark_verifier_peak_mb="100",
                        raw_verifier_peak_mb="3", mldsa_verifier_peak_mb="4",
                        verify_advantage_confirmed="0", verify_delta_mean_ms="-1",
                        verify_delta_ci95_low="-1.2", verify_delta_ci95_high="-0.8",
                        wire_reduction_pct="20")
            first = dict(base, n="5")
            second = dict(base, n="10", t="7", raw_decode_verify_ms="3",
                          verify_advantage_confirmed="1", break_even_median="500",
                          verify_delta_mean_ms="1", verify_delta_ci95_low="0.8",
                          verify_delta_ci95_high="1.2")
            write_csv(folder / "scaling.csv", fields, [first, second])
            write_csv(folder / "manifest.csv", ("n", "t", "status", "reason"), [
                {"n": "5", "t": "4", "status": "complete", "reason": ""},
                {"n": "10", "t": "7", "status": "complete", "reason": ""},
                {"n": "100", "t": "67", "status": "not_selected_ram",
                 "reason": "insufficient RAM"},
            ])
            result = self.run_plot(folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (folder / "plots/overview.md").read_text(encoding="utf-8")
            self.assertIn("N=10, t=7", text)
            self.assertIn("not_selected_ram", text)
            self.assertIn("| 5 | 4 | 48 |", text)
            self.assertNotIn("| 100 | 67 | 48 |", text)
            for figure in (folder / "plots").glob("*.svg"):
                ET.parse(figure)
            self.assertEqual(len(list((folder / "plots").glob("*.svg"))), 5)

            write_csv(folder / "manifest.csv", ("n", "t", "status", "reason"), [
                {"n": "5", "t": "4", "status": "complete", "reason": ""},
                {"n": "10", "t": "7", "status": "unstable", "reason": "drift"},
            ])
            rejected = self.run_plot(folder)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not complete", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
