#!/usr/bin/env python3
"""Small contract checks for the CSV plotting tool (no external packages)."""

import csv
import hashlib
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


def fixed_campaign(folder, status="complete", extra=()):
    """A minimal benchmark.sh directory, sealed the way benchmark.sh seals it."""
    fields = ("target", "metric", "unit", "n", "q1", "median", "q3")
    write_csv(folder / "summary.csv", fields, [
        {"target": "raw_agg", "metric": "decode_verify_per_item",
         "unit": "ms", "n": "1", "q1": "0.25", "median": "0.25", "q3": "0.25"},
        *extra,
    ])
    for name in ("summary.txt", "runs.csv", "samples.csv"):
        (folder / name).write_text(name + "\n", encoding="utf-8")
    (folder / "status.txt").write_text(f"{status}\ncampaign test\n", encoding="utf-8")
    if status == "complete":
        lines = []
        for name in ("runs.csv", "samples.csv", "summary.csv", "summary.txt"):
            digest = hashlib.sha256((folder / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (folder / "outputs.sha256").write_text("".join(lines), encoding="utf-8")


class PlotBenchmarksTest(unittest.TestCase):
    def run_plot(self, folder):
        return subprocess.run(
            [sys.executable, "-B", str(TOOL), str(folder)],
            capture_output=True, text=True, check=False,
        )

    def test_fixed_campaign_marks_single_run_without_uncertainty(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder)
            result = self.run_plot(folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (folder / "plots/overview.md").read_text(encoding="utf-8")
            self.assertIn("n=1 there is no uncertainty estimate", text)
            self.assertIn("| 1 | 0.250 | — | ms |", text)
            for figure in (folder / "plots").glob("*.svg"):
                ET.parse(figure)
            self.assertEqual(len(list((folder / "plots").glob("*.svg"))), 6)

    def assert_refused(self, folder, reason):
        result = self.run_plot(folder)
        self.assertNotEqual(result.returncode, 0, f"plotted a campaign with {reason}")
        self.assertFalse((folder / "plots").exists(), f"wrote plots for {reason}")

    def test_fixed_campaign_requires_complete_and_sealed_outputs(self):
        for status in ("failed", "running"):
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                fixed_campaign(folder, status)
                self.assert_refused(folder, f"status {status}")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder)
            (folder / "status.txt").unlink()
            self.assert_refused(folder, "no status.txt")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder)
            with (folder / "summary.csv").open("a", encoding="utf-8") as stream:
                stream.write("verifier,decode_verify_per_item,ms,1,9,9,9\n")
            self.assert_refused(folder, "a summary altered after sealing")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder)
            (folder / "outputs.sha256").unlink()
            self.assert_refused(folder, "no outputs.sha256")

    def test_peak_memory_names_its_source_and_never_plots_a_missing_reading(self):
        def peak(target, metric, median):
            return {"target": target, "metric": metric, "unit": "MiB", "n": "3",
                    "q1": median, "median": median, "q3": median}
        # Without `time -v` there are no kernel rows: the figure falls back to
        # VmHWM for every target and says so.
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder, extra=[peak("raw_agg", "peak_rss_vmhwm", "3"),
                                          peak("verifier", "peak_rss_vmhwm", "110")])
            result = self.run_plot(folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            figure = (folder / "plots/peak_memory.svg").read_text(encoding="utf-8")
            self.assertIn("VmHWM", figure)
            self.assertNotIn("Kernel ru_maxrss", figure)
        # One target without a kernel reading moves the whole figure to VmHWM
        # rather than mixing sources or drawing that target at zero.
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder, extra=[peak("raw_agg", "peak_rss_vmhwm", "3"),
                                          peak("raw_agg", "peak_rss_kernel", "3.4"),
                                          peak("verifier", "peak_rss_vmhwm", "110")])
            self.assertEqual(self.run_plot(folder).returncode, 0)
            figure = (folder / "plots/peak_memory.svg").read_text(encoding="utf-8")
            self.assertIn("VmHWM", figure)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fixed_campaign(folder, extra=[peak("raw_agg", "peak_rss_vmhwm", "3"),
                                          peak("raw_agg", "peak_rss_kernel", "3.4")])
            self.assertEqual(self.run_plot(folder).returncode, 0)
            figure = (folder / "plots/peak_memory.svg").read_text(encoding="utf-8")
            self.assertIn("Kernel ru_maxrss", figure)

    def test_scaling_campaign_excludes_unmeasured_points(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fields = ("n", "t", "observations", "prove_ms",
                      "snark_decode_verify_ms", "raw_decode_verify_ms",
                      "mldsa_decode_verify_ms", "snark_record_bytes",
                      "raw_record_bytes", "mldsa_record_bytes",
                      "prover_peak_mib", "snark_verifier_peak_mib",
                      "raw_verifier_peak_mib", "mldsa_verifier_peak_mib",
                      "verify_advantage_confirmed", "break_even_elapsed_median",
                      "verify_delta_mean_ms", "verify_delta_ci95_low",
                      "verify_delta_ci95_high", "wire_reduction_pct")
            base = dict.fromkeys(fields, "")
            base.update(t="4", observations="48", prove_ms="500",
                        snark_decode_verify_ms="2", raw_decode_verify_ms="1",
                        mldsa_decode_verify_ms="1.5", snark_record_bytes="4000",
                        raw_record_bytes="5000", mldsa_record_bytes="9000",
                        prover_peak_mib="700", snark_verifier_peak_mib="100",
                        raw_verifier_peak_mib="3", mldsa_verifier_peak_mib="4",
                        verify_advantage_confirmed="0", verify_delta_mean_ms="-1",
                        verify_delta_ci95_low="-1.2", verify_delta_ci95_high="-0.8",
                        wire_reduction_pct="20")
            first = dict(base, n="5")
            second = dict(base, n="10", t="7", raw_decode_verify_ms="3",
                          verify_advantage_confirmed="1", break_even_elapsed_median="500",
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

    def test_scaling_memory_reports_its_source_and_rejects_a_zero_peak(self):
        fields = ("n", "t", "observations", "prove_ms",
                  "snark_decode_verify_ms", "raw_decode_verify_ms",
                  "mldsa_decode_verify_ms", "snark_record_bytes",
                  "raw_record_bytes", "mldsa_record_bytes",
                  "prover_peak_mib", "snark_verifier_peak_mib",
                  "raw_verifier_peak_mib", "mldsa_verifier_peak_mib",
                  "verify_advantage_confirmed", "break_even_elapsed_median",
                  "verify_delta_mean_ms", "verify_delta_ci95_low",
                  "verify_delta_ci95_high", "wire_reduction_pct", "peak_rss_source")
        row = dict.fromkeys(fields, "")
        row.update(n="5", t="4", observations="3", prove_ms="500",
                   snark_decode_verify_ms="2", raw_decode_verify_ms="1",
                   mldsa_decode_verify_ms="1.5", snark_record_bytes="4000",
                   raw_record_bytes="5000", mldsa_record_bytes="9000",
                   prover_peak_mib="700", snark_verifier_peak_mib="100",
                   raw_verifier_peak_mib="3", mldsa_verifier_peak_mib="4",
                   verify_advantage_confirmed="0", verify_delta_mean_ms="-1",
                   wire_reduction_pct="20", peak_rss_source="vmhwm")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            write_csv(folder / "scaling.csv", fields, [row])
            result = self.run_plot(folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("| vmhwm |", (folder / "plots/overview.md").read_text(encoding="utf-8"))
            self.assertIn("process VmHWM",
                          (folder / "plots/memory_scaling.svg").read_text(encoding="utf-8"))
        for change in ({"raw_verifier_peak_mib": "0"}, {"peak_rss_source": "guess"}):
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                write_csv(folder / "scaling.csv", fields, [dict(row, **change)])
                self.assertNotEqual(self.run_plot(folder).returncode, 0, change)


if __name__ == "__main__":
    unittest.main()
