# Data of the ML-DSA statement digest experiment

One directory per run of `tools/mldsa_statement_experiment.sh`, named after the
compiler that built the binary. The note that reads them is
[`../../mldsa-statement-digest.md`](../../mldsa-statement-digest.md).

Each directory holds `env.txt`, `runs.csv`, `summary.csv`, `report.txt`,
`logs.sha256` (hashes of the per-process logs, which are not kept) and
`outputs.sha256` (hashes of the other five files; check with
`sha256sum -c outputs.sha256`).

## Redaction

Two things that identify the machine and say nothing about the measurement
were replaced after the runs, in `env.txt` and `report.txt` only:

- the host name, now `<redacted>`;
- absolute paths: the repository checkout is `<repo>`, a temporary build
  directory is `<tmp>`.

No number, parameter, compiler version or binary hash was touched, and
`runs.csv`, `summary.csv` and `logs.sha256` are byte-identical to what the
script wrote. `outputs.sha256` was regenerated over the redacted files, so it
verifies what is published here. The hashes the script originally recorded for
the two edited files were:

| run | `env.txt` as written by the script | `report.txt` as written by the script |
|---|---|---|
| `rust-1.98.1` | `275f4a1db309d3454bbfa9f6694d4af093efb31e356621b84b770c8d77b68ebf` | `4d6e25f2f376a98b6b9cb8c67de7fe31b15dbfe02d54de6e0479de69b1fef0fe` |
| `rust-1.90.0` | `0671cbdd44a6d65061660950ac67656a462bb1904edeb8d851acff1b2bf629b7` | `66cba58095a3cfa1abb9d88d3a9e49e0fb1ba29180d6fa2642088d07e5c0ae3c` |
| `rust-nightly-1.97` | `d46d0d00ed195b707cd2aac877d0ee5f5e328860143cc63941f561e975cfc666` | `3d4cd68a3e14dfade3d68f182abf94019d877c99839410706920bc40c708d856` |

A rerun writes the host name and the absolute paths of the machine it runs on
into its own output directory, which `.gitignore` excludes.
