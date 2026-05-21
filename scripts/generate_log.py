#!/usr/bin/env python3
"""Seedable test-data generator for log-analyzer.

Pure stdlib standalone — does NOT import from log_analyzer/.

Usage:
    python scripts/generate_log.py --lines 10000 --seed 42 --output sample.log
    python scripts/generate_log.py --lines 500 --anomaly-rate 0.20 > messy.log
"""
import argparse
import json
import random
import string
import sys
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
_PATHS = [
    "/api/users",
    "/api/users/12",
    "/api/users/34",
    "/api/users/550e8400-e29b-41d4-a716-446655440000",
    "/api/login",
    "/api/reports",
    "/api/export",
    "/api/health",
    "/api/orders/9971",
    "/api/orders/abcdef1234567890ab",
]
_IPS = ["192.168.1.42", "10.0.0.7", "172.16.0.3", "10.0.0.9", "203.0.113.17"]
_STATUSES = [200, 200, 200, 201, 301, 401, 403, 404, 500, 502]
_USER_AGENTS = [
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '"curl/7.88.1"',
    '"python-requests/2.31.0"',
    '"Googlebot/2.1 (+http://www.google.com/bot.html)"',
]
_STACK_FRAMES = [
    "Traceback (most recent call last):",
    '  File "app.py", line 42, in handle_request',
    '  File "db.py", line 17, in query',
    "Caused by: ConnectionRefusedError: [Errno 111] Connection refused",
    "  at com.example.Service.process(Service.java:101)",
]
_PARTIAL_PREFIXES = [
    "partial-write-",
    "2024-03-",
    "10.0.",
    "GET /api",
    "---",
    "=====",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fields(rng, ts):
    """Return (ip, method, path, status, response_ms) for a well-formed line."""
    return (
        rng.choice(_IPS),
        rng.choice(_METHODS),
        rng.choice(_PATHS),
        rng.choice(_STATUSES),
        rng.randint(10, 2000),
    )


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Normal-line generators (each takes rng, ts; returns a string)
# ---------------------------------------------------------------------------

def gen_standard_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return f"{_iso(ts)} {ip} {method} {path} {status} {ms}ms"


def gen_lowercase_method_line(rng, ts):
    """Deviation #10 — lowercase HTTP method."""
    ip, method, path, status, ms = _fields(rng, ts)
    return f"{_iso(ts)} {ip} {method.lower()} {path} {status} {ms}ms"


def gen_alt_timestamp_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    fmt = rng.choice([
        ts.strftime("%Y/%m/%d %H:%M:%S"),
        ts.strftime("%d-%b-%Y %H:%M:%S"),
    ])
    return f"{fmt} {ip} {method} {path} {status} {ms}ms"


def gen_epoch_timestamp_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return f"{int(ts.timestamp())} {ip} {method} {path} {status} {ms}ms"


def gen_json_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return json.dumps({
        "timestamp": _iso(ts),
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "response_ms": ms,
    })


def gen_line_with_extra_quoted(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    ua = rng.choice(_USER_AGENTS)
    return f"{_iso(ts)} {ip} {method} {path} {status} {ms}ms {ua}"


def gen_missing_status_line(rng, ts):
    ip, method, path, _, ms = _fields(rng, ts)
    return f"{_iso(ts)} {ip} {method} {path} - {ms}ms"


def gen_seconds_response_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return f"{_iso(ts)} {ip} {method} {path} {status} {ms / 1000.0:.3f}s"


def gen_bare_response_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return f"{_iso(ts)} {ip} {method} {path} {status} {ms}"


# ---------------------------------------------------------------------------
# Anomaly generators
# ---------------------------------------------------------------------------

def gen_blank_line(rng, ts):
    return ""


def gen_stack_trace_line(rng, ts):
    return rng.choice(_STACK_FRAMES)


def gen_partial_write_line(rng, ts):
    return rng.choice(_PARTIAL_PREFIXES) + str(rng.randint(1, 999))


def gen_unclosed_quote_line(rng, ts):
    ip, method, path, status, ms = _fields(rng, ts)
    return (
        f"{_iso(ts)} {ip} {method} {path} {status} {ms}ms "
        '"broken user agent not closed'
    )


def gen_garbage_line(rng, ts):
    chars = string.printable[:80]
    return "".join(rng.choice(chars) for _ in range(rng.randint(10, 60)))


def gen_truncated_json_line(rng, ts):
    ip, _, path, _, _ = _fields(rng, ts)
    full = json.dumps({"timestamp": _iso(ts), "ip": ip, "path": path})
    cut = rng.randint(len('{"timestamp"'), len(full) - 1)
    return full[:cut]


# ---------------------------------------------------------------------------
# Weight tables
# ---------------------------------------------------------------------------

_NORMAL = [
    (gen_standard_line,           0.57),
    (gen_lowercase_method_line,   0.08),
    (gen_alt_timestamp_line,      0.08),
    (gen_epoch_timestamp_line,    0.04),
    (gen_json_line,               0.08),
    (gen_line_with_extra_quoted,  0.05),
    (gen_missing_status_line,     0.02),
    (gen_seconds_response_line,   0.02),
    (gen_bare_response_line,      0.01),
]  # sum: 0.95

_ANOMALY = [
    (gen_blank_line,              0.010),
    (gen_stack_trace_line,        0.015),
    (gen_partial_write_line,      0.010),
    (gen_unclosed_quote_line,     0.005),
    (gen_garbage_line,            0.005),
    (gen_truncated_json_line,     0.005),
]  # sum: 0.05


def _build(anomaly_rate=None):
    """Return (funcs, weights). Rescales if anomaly_rate overrides the default 5%."""
    normal = list(_NORMAL)
    anomaly = list(_ANOMALY)

    if anomaly_rate is not None:
        rate = max(0.0, min(1.0, anomaly_rate))
        n_total = sum(w for _, w in normal)
        a_total = sum(w for _, w in anomaly)
        normal = [(f, w / n_total * (1.0 - rate)) for f, w in normal]
        anomaly = [(f, w / a_total * rate) for f, w in anomaly]

    combined = normal + anomaly
    return [f for f, _ in combined], [w for _, w in combined]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Generate synthetic server log data.")
    p.add_argument("--lines",        type=int,   default=10_000,
                   help="Number of log lines to emit (default: 10000)")
    p.add_argument("--seed",         type=int,   default=42,
                   help="RNG seed for reproducibility (default: 42)")
    p.add_argument("--output",                   default=None,
                   help="Output file path (default: stdout)")
    p.add_argument("--anomaly-rate", type=float, default=None,
                   help="Override anomaly fraction 0.0–1.0 (default: ~0.05)")
    args = p.parse_args()

    rng = random.Random(args.seed)
    funcs, weights = _build(args.anomaly_rate)

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        ts = datetime(2024, 3, 15, 14, 23, 1, tzinfo=timezone.utc)
        for _ in range(args.lines):
            ts += timedelta(milliseconds=rng.randint(100, 5000))
            func = rng.choices(funcs, weights=weights, k=1)[0]
            out.write(func(rng, ts) + "\n")
    finally:
        if args.output:
            out.close()


if __name__ == "__main__":
    main()
