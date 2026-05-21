from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Union


@dataclass(frozen=True)
class Event:
    """A successfully parsed log entry, normalized to canonical shape."""
    timestamp: Optional[datetime]
    ip: Optional[str]
    method: Optional[str]
    path: str
    raw_path: str
    status: Optional[int]
    response_ms: Optional[float]
    raw_status: Optional[str] = None
    raw_response_time: Optional[str] = None
    raw_extra: Optional[str] = None
    source_format: str = "standard"
    line_no: int = 0


class AnomalyKind(str, Enum):
    BLANK = "blank"
    STACK_TRACE_CONTINUATION = "stack_trace_continuation"
    JSON_PARSE_ERROR = "json_parse_error"
    UNCLOSED_QUOTE = "unclosed_quote"
    UNKNOWN_FORMAT = "unknown_format"
    PARSER_ERROR = "parser_error"


@dataclass(frozen=True)
class Anomaly:
    kind: AnomalyKind
    raw: str
    line_no: int
    reason: str = ""


class FieldWarningKind(str, Enum):
    INVALID_STATUS = "invalid_status"
    INVALID_RESPONSE_TIME = "invalid_response_time"


ParseResult = Union[Event, Anomaly]
