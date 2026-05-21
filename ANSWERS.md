# ANSWERS.md

## Q1 — How to run

**Requirements:** Python 3.10+. No packages needed at runtime.

```
# Analyze a log file
python3 loganalyze.py path/to/access.log

# Same, gzip-compressed (auto-detected)
python3 loganalyze.py path/to/access.log.gz

# Machine-readable JSON output
python3 loganalyze.py path/to/access.log --json

# Generate a sample log file (stdlib-only, no deps)
python3 scripts/generate_log.py --lines 10000 --seed 42 --output sample.log

# Run the test suite (dev dep: pytest)
pip install pytest
python3 -m pytest
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
rt_raw = data.get("response_ms") or data.get("response_time") or data.get("duration")
```

This silently substitutes when the first key is present but *falsy* — and
`0` is falsy. `response_ms: 0` is a sub-millisecond cached page response: a
real, valid measurement. With the buggy idiom, that `0` falls through to
`response_time` or `duration` — a totally different field, possibly in
different units — corrupting the latency percentile aggregates. The report
renders cleanly while presenting wrong numbers. That is worse than a crash:
a crash is loud.

The code uses explicit key presence checks instead:

```python
# parser.py:83-90
if "response_ms" in data:
    raw_rt = data["response_ms"]
elif "response_time" in data:
    raw_rt = data["response_time"]
elif "duration" in data:
    raw_rt = data["duration"]
else:
    raw_rt = None
```

The same pattern applies to the timestamp key lookup (`timestamp` vs `ts`)
at lines 68–73.

**Without this fix:** a line like `{"response_ms": 0, "duration": 1800, ...}`
silently attributes latency to `duration` — a session-length field measured
in seconds in some log shippers — completely corrupting p50/p95/p99 for that
endpoint.

The fix is tested in `tests/test_parser.py` (`response_ms: 0` is attributed
to `response_ms`, not `duration`). Note: `timestamp: 0` (Unix epoch 1970) is
separately rejected by the year-2000 floor in `normalizers.py:24`, so the
timestamp case is caught at a different layer — but the same principle applies
to any future `0`-valued key that is legitimate.

---

## Q4 — AI usage

I used Claude Code throughout the project as a coding assistant, reviewer, and pair-programming tool.

The main places I used it were:

- planning the implementation from the assessment requirements
- identifying edge cases for malformed logs and weird input formats
- generating and refining tests
- implemention after planning phase of the parser, analyzer, reporter, and CLI
- reviewing the finished code for bugs, missing edge cases, and documentation

I reviewed the code, ran tests, asked follow-up questions, and changed or removed things where they did not make sense.

A few concrete examples (drafted by claude based on our conversations during the sessions):

- Claude suggested a BrokenPipeError handler that closed sys.stdout. That broke pytest’s capsys fixture, so I removed the close and kept the handler simpler.
- Claude added a parse_extra_field() helper for tokenizing quoted user-agent/referrer fields. It had tests, but nothing actually used it, so I removed it as speculative API.
- Claude suggested removing the fallback "other" branch in status_class. I kept the branch because an explicit fallback is safer than an accidental implicit None.
- Claude flagged some issues during audit that I rejected after verifying the code, such as a claim that the standard regex would fail on - response fields. The regex already handled that case.
- Rejected accepting negative response times — invalid operational data shouldn't pollute p95/p99. Field becomes None with a warning; line still parses.
- Rejected lumping parser exceptions into UNKNOWN_FORMAT — would hide our own bugs as bad input. Became distinct PARSER_ERROR anomaly.
- Cut reservoir sampling — overengineering for "few hundred thousand lines." Simple LatencyStore with exact percentiles instead.
- Reframed priorities to behavior over design — evaluator cares whether the tool crashes on weird input, not whether I used a Strategy Pattern. Promoted adversarial testing into the main build phase.

Overall, AI helped me move rapidly and catch more edge cases.

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

**4. STANDARD_RE requires a status token (`log_analyzer/parser.py`)**

`STANDARD_RE` (`parser.py:43`) matches status as `\d+|-`. If a logger omits
the status field entirely (no `-` substitution), the regex fails and the line
falls through to `UNKNOWN_FORMAT`. The generator always emits the `-` form,
which is what every standard log format (Apache CLF, Nginx) uses, so this
case is rare in practice.

*Why we didn't fix it:* making status optional creates token-position
ambiguity — `200ms` (response time) and `200` (status) are both `\S+`, and
heuristic guessing is worse than surfacing the anomaly honestly. Positionally-
omitted status lands in `UNKNOWN_FORMAT` with its raw line preserved in
samples, which is correct under the "never silently drop data" principle.
