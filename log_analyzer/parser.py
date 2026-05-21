import json
import re
import shlex
from typing import Callable, List, Optional

from log_analyzer.models import Anomaly, AnomalyKind, Event, ParseResult, SourceFormat
from log_analyzer.normalizers import normalize_response_time, normalize_status, normalize_timestamp

# ---------------------------------------------------------------------------
# Internal sentinels — never escape this module
# ---------------------------------------------------------------------------

class _ParserSentinel(Exception):
    pass

class _JsonParseFailed(_ParserSentinel):
    pass

class _UnclosedQuote(_ParserSentinel):
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Deviation #1: prefixes matched against the stripped line (no leading whitespace).
# Spec had "  at " and "  File " which only matched lines starting with exactly
# two spaces — stripped comparison makes this format-agnostic.
STACK_TRACE_PREFIXES = (
    "Traceback",
    "at ",
    'File "',
    "Caused by:",
)

# Deviation #10: [A-Za-z]+ instead of [A-Z]+; uppercased on construction.
STANDARD_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<ip>\S+)\s+"
    r"(?P<method>[A-Za-z]+)\s+"
    r"(?P<path>\S+)\s+"
    r"(?P<status>\d+|-)\s+"
    r"(?P<response>\S+)"
    r"(?P<extra>\s+.*)?$"
)

ParseStrategy = Callable[[str, int], Optional[Event]]


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

def parse_json_line(line: str, line_no: int) -> Optional[Event]:
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        raise _JsonParseFailed()

    if not isinstance(data, dict):
        return None  # JSON array or scalar — not a log entry

    # Deviation #2: explicit key checks, not falsy or-fallback.
    # data.get("timestamp") or data.get("ts") would silently skip timestamp:0.
    if "timestamp" in data:
        ts_raw = data["timestamp"]
    elif "ts" in data:
        ts_raw = data["ts"]
    else:
        ts_raw = None

    ts = normalize_timestamp(ts_raw)
    if ts is None:
        return None  # valid JSON but not a log entry — fall through to next strategy

    raw_path = data.get("path", "")
    raw_status = data.get("status")

    # Deviation #2: same fix for response time — response_ms:0 is a valid cached-page time.
    if "response_ms" in data:
        raw_rt = data["response_ms"]
    elif "response_time" in data:
        raw_rt = data["response_time"]
    elif "duration" in data:
        raw_rt = data["duration"]
    else:
        raw_rt = None

    return Event(
        timestamp=ts,
        ip=data.get("ip"),
        method=(data.get("method") or "").upper() or None,
        path=raw_path,            # deviation #7: analyzer normalizes, not parser
        raw_path=raw_path,
        status=normalize_status(raw_status),
        response_ms=normalize_response_time(raw_rt),
        raw_status=str(raw_status) if raw_status is not None else None,
        raw_response_time=str(raw_rt) if raw_rt is not None else None,
        raw_extra=None,
        source_format=SourceFormat.JSON,
        line_no=line_no,
    )


def parse_standard_line(line: str, line_no: int) -> Optional[Event]:
    m = STANDARD_RE.match(line)
    if not m:
        return None

    ts = normalize_timestamp(m.group("timestamp"))
    if ts is None:
        return None  # matched regex but timestamp unparseable — let alt strategy try

    raw_path = m.group("path")
    raw_status = m.group("status")
    raw_response = m.group("response")
    extra = m.group("extra")

    return Event(
        timestamp=ts,
        ip=m.group("ip"),
        method=m.group("method").upper(),  # deviation #10: uppercase after [A-Za-z]+ match
        path=raw_path,                      # deviation #7
        raw_path=raw_path,
        status=normalize_status(raw_status),
        response_ms=normalize_response_time(raw_response),
        raw_status=raw_status,
        raw_response_time=raw_response,
        raw_extra=extra.strip() if extra else None,
        source_format=SourceFormat.STANDARD,
        line_no=line_no,
    )


def parse_alt_format_line(line: str, line_no: int) -> Optional[Event]:
    """Handles lines with two-token timestamps (e.g. '2024/03/15 14:23:01').

    Deviation #11: only tries the 2-token case. Single-token timestamps
    (ISO, epoch) are already handled by parse_standard_line via STANDARD_RE.
    """
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        raise _UnclosedQuote()

    # Need 7+ tokens: 2 (timestamp) + ip + method + path + status + response
    if len(tokens) < 7:
        return None

    ts_str = tokens[0] + " " + tokens[1]
    ts = normalize_timestamp(ts_str)
    if ts is None:
        return None

    ip = tokens[2]
    method_raw = tokens[3]
    raw_path = tokens[4]
    raw_status = tokens[5]
    raw_response = tokens[6]
    extra_tokens = tokens[7:]

    if not method_raw.isalpha():
        return None  # sanity: HTTP methods are alphabetic only

    return Event(
        timestamp=ts,
        ip=ip,
        method=method_raw.upper(),
        path=raw_path,            # deviation #7
        raw_path=raw_path,
        status=normalize_status(raw_status),
        response_ms=normalize_response_time(raw_response),
        raw_status=raw_status,
        raw_response_time=raw_response,
        raw_extra=" ".join(extra_tokens) if extra_tokens else None,
        source_format=SourceFormat.ALTERNATE,
        line_no=line_no,
    )


# ---------------------------------------------------------------------------
# Strategy registration
# ---------------------------------------------------------------------------

DEFAULT_STRATEGIES: List[ParseStrategy] = [
    parse_json_line,        # JSON first — { is an unambiguous discriminator
    parse_standard_line,    # dominant format (~73% of synthetic mix)
    parse_alt_format_line,  # slowest (shlex.split allocates) — long-tail fallback
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Parser:
    def __init__(
        self,
        strategies: Optional[List[ParseStrategy]] = None,
        debug: bool = False,
    ):
        self.strategies = strategies if strategies is not None else DEFAULT_STRATEGIES
        self.debug = debug

    def parse(self, raw_line: str, line_no: int) -> ParseResult:
        if not raw_line or not raw_line.strip():
            return Anomaly(AnomalyKind.BLANK, raw_line, line_no)

        stripped = raw_line.strip()

        if self._looks_like_stack_trace(stripped):
            return Anomaly(AnomalyKind.STACK_TRACE_CONTINUATION, raw_line, line_no)

        for strategy in self.strategies:
            try:
                event = strategy(stripped, line_no)
                if event is not None:
                    return event
            except _JsonParseFailed:
                return Anomaly(
                    AnomalyKind.JSON_PARSE_ERROR, raw_line, line_no,
                    reason="JSON decode failed",
                )
            except _UnclosedQuote:
                return Anomaly(
                    AnomalyKind.UNCLOSED_QUOTE, raw_line, line_no,
                    reason="unclosed quote in line",
                )
            except Exception as exc:
                if self.debug:
                    raise
                return Anomaly(
                    AnomalyKind.PARSER_ERROR, raw_line, line_no,
                    reason=f"{type(exc).__name__}: {exc}",
                )

        return Anomaly(AnomalyKind.UNKNOWN_FORMAT, raw_line, line_no, reason="no strategy matched")

    @staticmethod
    def _looks_like_stack_trace(line: str) -> bool:
        return any(line.startswith(p) for p in STACK_TRACE_PREFIXES)
