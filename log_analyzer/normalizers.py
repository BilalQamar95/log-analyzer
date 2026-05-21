import math
import re
from datetime import datetime, timezone
from typing import Any, Optional

__all__ = [
    "normalize_timestamp",
    "normalize_response_time",
    "normalize_status",
    "normalize_path",
    "status_class",
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
]

# Epoch floor raised to year 2000 — epoch 0 (common logger default/sentinel) treated as missing
EPOCH_SECONDS_MIN = 946_684_800        # 2000-01-01 UTC
EPOCH_SECONDS_MAX = 4_102_444_800      # 2100-01-01 UTC
EPOCH_MILLIS_MIN  = 1_000_000_000_000  # ~2001-09-09 UTC
EPOCH_MILLIS_MAX  = 4_102_444_800_000  # 2100-01-01 UTC


def normalize_timestamp(value: Any) -> Optional[datetime]:
    """Parse any supported timestamp format. Returns UTC-aware datetime or None."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    # Gate epoch parsing on clearly numeric strings to avoid float("nan")/float("inf")
    # and scientific notation (e.g. "1.5e9") being silently accepted as timestamps.
    if s.lstrip("-").replace(".", "", 1).isdigit():
        try:
            ts = float(s)
            if math.isfinite(ts):
                if EPOCH_SECONDS_MIN <= ts <= EPOCH_SECONDS_MAX:
                    return datetime.fromtimestamp(ts, tz=timezone.utc)
                if EPOCH_MILLIS_MIN <= ts <= EPOCH_MILLIS_MAX:
                    return datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def normalize_response_time(value: Any) -> Optional[float]:
    """Normalize response time to milliseconds. Returns None for missing or invalid values."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s or s == "-":
        return None

    try:
        if s.endswith("ms"):
            ms = float(s[:-2])
        elif s.endswith("s"):
            ms = float(s[:-1]) * 1000.0
        else:
            ms = float(s)  # bare number assumed milliseconds
    except ValueError:
        return None

    if not math.isfinite(ms) or ms < 0:
        return None

    return ms


def normalize_status(value: Any) -> Optional[int]:
    """Return HTTP status code as int in [100, 599], or None."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == "-":
        return None
    try:
        code = int(s)
    except ValueError:
        return None
    if not 100 <= code <= 599:
        return None
    return code


_ID_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# Matches 16+ hex chars. Short hex IDs (8-12 chars) are intentionally not collapsed
# to avoid false-positives on hex-looking slugs. Documented as an honest gap.
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


def normalize_path(path: str) -> str:
    """Collapse dynamic path segments so /api/users/12 and /api/users/13 aggregate together.

    Strips query strings and URL fragments. Normalizes trailing slashes (except root /).
    """
    if not path:
        return path
    base = path.split("?", 1)[0].split("#", 1)[0]
    if len(base) > 1 and base.endswith("/"):
        base = base[:-1]
    parts = base.split("/")
    normalized = []
    for part in parts:
        if _UUID_SEGMENT.match(part):
            normalized.append(":uuid")
        elif _ID_SEGMENT.match(part):
            normalized.append(":id")
        elif _HEX_SEGMENT.match(part):
            normalized.append(":hex")
        else:
            normalized.append(part)
    return "/".join(normalized)


def status_class(status: Optional[int]) -> str:
    """Return the HTTP status class string for reporting."""
    if status is None:
        return "missing"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"
