# log-analyzer

Streaming analyzer for messy server log files. Parses standard, JSON, and
alternate-timestamp formats; degrades gracefully on malformed input — skipped
lines are counted and surfaced, never silently dropped.

## Requirements

Python 3.10 or later. The runtime uses only the standard library — no install
step needed.

`pytest` is the only dev dependency, used only to run the test suite.

## Run

```
python loganalyze.py path/to/access.log
```

Gzip-compressed logs are auto-detected via magic-byte sniff:

```
python loganalyze.py path/to/access.log.gz
```

### Flags

| Flag            | Purpose                                                       |
|-----------------|---------------------------------------------------------------|
| `--json`        | Machine-readable JSON snapshot to stdout                      |
| `--slowest N`   | Show top N slowest endpoints by p95 latency (default 10)      |
| `--errors`      | Show only the error-heavy endpoints section                   |
| `--anomalies`   | Show only anomaly samples (full list, not truncated)          |
| `--status CODE` | Filter to a status code (`500`) or class (`4xx`, `5xx`, etc.) |

**Exit codes:** `0` on successful analysis — including files with 100%
anomalous lines (anomalies are data, not failure). `2` when the file is
inaccessible (not found / is a directory / permission denied / corrupt gzip).

## Generating sample data

A seedable generator produces representative logs matching the documented
5–10% anomaly mix:

```
python scripts/generate_log.py --lines 10000 --seed 42 --output sample.log
```

To generate a fully-clean baseline (zero anomalies):

```
python scripts/generate_log.py --lines 2000 --anomaly-rate 0.0 --output clean.log
```

Same seed produces byte-identical output. Python's `random` module guarantees
stability within a minor version.

## Tests

```
pip install pytest
python -m pytest
```

273 tests across unit (normalizers, parser, analyzer, reporter, CLI) and
integration (clean/messy/adversarial fixtures, flag matrix, subprocess
broken-pipe check, acceptance smoke covering all fixtures × all flags).

## Layout

```
loganalyze.py                   thin entry point (5 lines)
log_analyzer/                   runtime package (stdlib-only)
  models.py                     Event, Anomaly, enums
  normalizers.py                pure field coercion — never raises
  parser.py                     strategy chain: JSON → standard → alt
  analyzer.py                   streaming aggregator + invariant check
  reporter.py                   TextReporter (12 sections) + JsonReporter
  cli.py                        argparse, gzip sniff, BOM, BrokenPipe, exit codes
scripts/
  generate_log.py               seedable test-data generator
tests/
  fixtures/
    clean.log                   2000-line fully-parsed baseline
    messy.log                   2000-line ~5% anomaly mix
    adversarial.log             hand-crafted edge cases (BOM, inf/nan, epoch 0, …)
  test_normalizers.py
  test_parser.py
  test_analyzer.py
  test_reporter.py
  test_cli.py
  test_integration.py
```
