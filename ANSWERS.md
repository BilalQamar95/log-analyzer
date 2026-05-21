# ANSWERS.md

## Q1 — How to run

**Requirements:** Python 3.10+. No packages needed at runtime.

```
# Analyze a log file
python loganalyze.py path/to/access.log

# Same, gzip-compressed (auto-detected)
python loganalyze.py path/to/access.log.gz

# Machine-readable JSON output
python loganalyze.py path/to/access.log --json

# Generate a sample log file (stdlib-only, no deps)
python scripts/generate_log.py --lines 10000 --seed 42 --output sample.log

# Run the test suite (dev dep: pytest)
pip install pytest
python -m pytest
```

Tested on Python 3.11. Works on 3.10+.

---

## Q2 — Stack choice

**Why Python stdlib:**

Text parsing, streaming aggregation, and tabular reporting are exactly the
problem domain the stdlib was designed for: `re` for regex strategies,
`json` for JSON-format lines, `datetime`/`gzip`/`argparse`/`collections`
for everything else. The "run on a fresh machine with one command" constraint
pushed hard toward zero install friction — a stdlib-only runtime delivers
that unconditionally.

**Worse choices:**

- **Node.js** — adds `npm install` plus async-IO plumbing that buys nothing
  on a CPU-bound, single-file, sequential text scan.
- **A web dashboard (Flask/FastAPI + browser UI)** — the evaluator runs the
  tool from a terminal against files they supply. A browser round-trip adds
  zero analytical value and requires a running server or a bundled frontend,
  neither of which fits "single command on a fresh machine."
- **Rust or Go** — faster runtime, but the evaluator has to install a
  toolchain. At the documented scale (a few hundred to a few hundred thousand
  lines) Python is plenty fast — the adversarial fixture runs end-to-end in
  well under a second.

---

## Q3 — One real edge case

**The falsy-fallback bug in JSON parsing** — `log_analyzer/parser.py` lines 68–92.

The naive idiom for multi-key JSON lookups is:

```python
ts_raw = data.get("timestamp") or data.get("ts")
```

This silently substitutes when the first key is present but *falsy* — and
`0` is falsy. `timestamp: 0` is the Unix epoch (1970-01-01T00:00:00Z), a
legitimate value in legacy log shippers. `response_ms: 0` is a cached page
with sub-millisecond latency, also legitimate.

The code uses explicit key presence checks instead:

```python
# parser.py:68-73
if "timestamp" in data:
    ts_raw = data["timestamp"]
elif "ts" in data:
    ts_raw = data["ts"]
else:
    ts_raw = None
```

And the same pattern for the three response-time keys (`response_ms`,
`response_time`, `duration`) at lines 83–90.

**Without this:** a log line like `{"timestamp": 0, "ip": "10.0.0.1", ...}`
would silently lose its timestamp. A line like `{"response_ms": 0, ...}`
would silently fall through to `duration` — a totally different field,
possibly in different units — corrupting the latency percentile aggregates.
The report would render cleanly while presenting wrong numbers. That is worse
than a crash: a crash is loud.

The fix is tested in `tests/test_parser.py` (cases: `timestamp: 0`
round-trips correctly; `response_ms: 0` is attributed to `response_ms`,
not `duration`).

---

## Q4 — AI usage

<!-- Fill this section in yourself before submitting. -->
<!-- Suggested structure: -->
<!--   - Which tool(s) you used (Claude, ChatGPT, Copilot, etc.)          -->
<!--   - What you asked / what prompts or tasks you delegated              -->
<!--   - What the AI produced                                              -->
<!--   - For at least one instance: what you changed about the output      -->
<!--     and why (the assessors want evidence of judgment, not just usage) -->

---

## Q5 — Honest gaps

Three real limitations, in rough order of impact:

**1. First-N anomaly sampling (`log_analyzer/analyzer.py`)**

Anomaly samples are stored as the first N lines of each kind (default cap: 5).
If a file has normal lines at the top and format drift halfway through, the
samples shown in the report are biased toward the start and may not represent
the actual anomaly pattern.

*Fix with another day:* swap the list-append for a reservoir sampler
(Algorithm R). The interface would stay identical — `add()` and
`get_samples()` — so no caller changes. The bias disappears.

**2. Multi-line stack-trace state tracking (`log_analyzer/parser.py`)**

The parser detects stack-trace *entry lines* via `STACK_TRACE_PREFIXES`
(`"Traceback"`, `"at "`, `"File \""`, `"Caused by:"`). Continuation lines
that don't start with one of these prefixes fall through to `UNKNOWN_FORMAT`
anomalies. In practice a 20-line Java stack trace produces one
`STACK_TRACE_CONTINUATION` anomaly and nineteen `UNKNOWN_FORMAT` anomalies,
inflating the unknown-format count and diluting sample quality.

*Fix with another day:* add a stateful flag (`_inside_stack_trace: bool`) to
`Parser`. When a `STACK_TRACE_PREFIXES` match fires, set the flag. Subsequent
lines are tagged `STACK_TRACE_CONTINUATION` until a blank line or a
parseable timestamp resets it.

**3. Short hex ID path segments (`log_analyzer/normalizers.py`)**

`_HEX_SEGMENT` requires 16+ characters to collapse a path segment to `:hex`.
Path segments like `/api/sessions/8a3f9c2b` (8–12 character hex IDs, common
in older services) are not collapsed, so `endpoint_request_counts` fragments
across IDs and the top-endpoints list becomes noisy.

*Fix with another day:* calibrate the threshold against real data, or add a
clustering pass that groups path segments by cardinality (segments appearing
in >N distinct paths with only alphanumeric variation get a `:id` label).
