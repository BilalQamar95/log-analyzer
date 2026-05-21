import os
import pytest
from log_analyzer.models import Anomaly, AnomalyKind, Event, SourceFormat
from log_analyzer.parser import (
    Parser,
    STACK_TRACE_PREFIXES,
    parse_alt_format_line,
    parse_json_line,
    parse_standard_line,
    parse_extra_field,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "adversarial.log")


# ---------------------------------------------------------------------------
# parse_json_line
# ---------------------------------------------------------------------------

class TestParseJsonLine:
    def test_full_valid(self):
        line = '{"timestamp":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"POST","path":"/api/login","status":401,"response_ms":89}'
        e = parse_json_line(line, 1)
        assert isinstance(e, Event)
        assert e.source_format == SourceFormat.JSON
        assert e.ip == "1.2.3.4"
        assert e.method == "POST"
        assert e.path == "/api/login"
        assert e.status == 401
        assert e.response_ms == pytest.approx(89.0)
        assert e.line_no == 1

    def test_ts_key_fallback(self):
        line = '{"ts":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"GET","path":"/x","status":200,"response_ms":10}'
        e = parse_json_line(line, 2)
        assert isinstance(e, Event)
        assert e.timestamp is not None

    def test_response_ms_zero_deviation2(self):
        # Deviation #2: response_ms:0 must NOT fall through to other response keys.
        line = '{"timestamp":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"GET","path":"/x","status":200,"response_ms":0,"duration":9999}'
        e = parse_json_line(line, 3)
        assert isinstance(e, Event)
        assert e.response_ms == pytest.approx(0.0)

    def test_lowercase_method_uppercased(self):
        line = '{"timestamp":"2024-03-15T14:23:01Z","method":"get","path":"/x","status":200,"response_ms":10}'
        e = parse_json_line(line, 1)
        assert isinstance(e, Event)
        assert e.method == "GET"

    def test_missing_path_defaults_empty(self):
        line = '{"timestamp":"2024-03-15T14:23:01Z","status":200,"response_ms":10}'
        e = parse_json_line(line, 1)
        assert isinstance(e, Event)
        assert e.path == ""

    def test_non_dict_array_returns_none(self):
        assert parse_json_line("[1,2,3]", 1) is None

    def test_non_dict_scalar_returns_none(self):
        # A JSON scalar doesn't start with { so returns None immediately
        assert parse_json_line("42", 1) is None

    def test_missing_timestamp_returns_none(self):
        line = '{"ip":"1.2.3.4","method":"GET","path":"/x","status":200}'
        assert parse_json_line(line, 1) is None

    def test_epoch_zero_timestamp_returns_none(self):
        # timestamp:0 is below EPOCH_SECONDS_MIN; normalize_timestamp returns None
        line = '{"timestamp":0,"ip":"1.2.3.4","method":"GET","path":"/x","status":200,"response_ms":10}'
        assert parse_json_line(line, 1) is None

    def test_non_json_prefix_returns_none(self):
        assert parse_json_line("not json", 1) is None

    def test_truncated_json_raises_json_parse_failed(self):
        from log_analyzer.parser import _JsonParseFailed
        with pytest.raises(_JsonParseFailed):
            parse_json_line('{"timestamp":"2024-03-15T14:23:01Z","ip"', 1)

    def test_raw_status_and_raw_response_time_stored(self):
        line = '{"timestamp":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"GET","path":"/x","status":200,"response_ms":142}'
        e = parse_json_line(line, 1)
        assert e.raw_status == "200"
        assert e.raw_response_time == "142"


# ---------------------------------------------------------------------------
# parse_standard_line
# ---------------------------------------------------------------------------

class TestParseStandardLine:
    @pytest.mark.parametrize("line,expected_method,expected_ms", [
        ("2024-03-15T14:23:01Z 1.2.3.4 GET /api/users 200 142ms",   "GET",    142.0),
        ("2024-03-15T14:23:01Z 1.2.3.4 post /api/login 401 89ms",   "POST",   89.0),   # lowercase → uppercase
        ("2024-03-15T14:23:01Z 1.2.3.4 DELETE /api/x 200 0.5s",     "DELETE", 500.0),  # seconds
        ("2024-03-15T14:23:01Z 1.2.3.4 GET /api/x 200 300",          "GET",    300.0),  # bare ms
        ("1710512581 1.2.3.4 GET /api/users 200 142ms",              "GET",    142.0),  # epoch timestamp
    ])
    def test_valid(self, line, expected_method, expected_ms):
        e = parse_standard_line(line, 1)
        assert isinstance(e, Event)
        assert e.method == expected_method
        assert e.response_ms == pytest.approx(expected_ms)
        assert e.source_format == SourceFormat.STANDARD

    def test_missing_status_dash(self):
        e = parse_standard_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 142ms", 1)
        assert isinstance(e, Event)
        assert e.status == 200

    def test_status_dash_normalizes_none(self):
        e = parse_standard_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api - 142ms", 1)
        assert isinstance(e, Event)
        assert e.status is None
        assert e.raw_status == "-"

    def test_extra_field_captured(self):
        e = parse_standard_line(
            '2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 142ms "Mozilla/5.0 (Windows)"', 1
        )
        assert isinstance(e, Event)
        assert e.raw_extra is not None
        assert "Mozilla" in e.raw_extra

    def test_path_not_normalized(self):
        # Deviation #7: parser emits raw path; analyzer normalizes
        e = parse_standard_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api/users/12 200 142ms", 1)
        assert isinstance(e, Event)
        assert e.path == "/api/users/12"
        assert e.raw_path == "/api/users/12"

    def test_two_token_timestamp_returns_none(self):
        # Alt-format line — standard regex fails (method position contains an IP)
        result = parse_standard_line("2024/03/15 14:23:01 1.2.3.4 GET /api 200 142ms", 1)
        assert result is None

    def test_non_matching_returns_none(self):
        assert parse_standard_line("not a log line", 1) is None
        assert parse_standard_line("Traceback (most recent call last):", 1) is None

    def test_unparseable_timestamp_returns_none(self):
        # Regex matches but normalize_timestamp returns None → strategy returns None
        # (This should only happen for exotic strings; most \S+ tokens either parse or don't match)
        # Use epoch-0 which is below the floor
        result = parse_standard_line("0 1.2.3.4 GET /api 200 142ms", 1)
        # "0" is below EPOCH_SECONDS_MIN floor → normalize_timestamp returns None → returns None
        assert result is None

    def test_invalid_status_still_produces_event(self):
        # Status 999 — regex matches, Event produced with status=None (field warning territory)
        e = parse_standard_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api 999 142ms", 1)
        assert isinstance(e, Event)
        assert e.status is None
        assert e.raw_status == "999"

    def test_negative_response_still_produces_event(self):
        e = parse_standard_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 -500ms", 1)
        assert isinstance(e, Event)
        assert e.response_ms is None
        assert e.raw_response_time == "-500ms"


# ---------------------------------------------------------------------------
# parse_alt_format_line
# ---------------------------------------------------------------------------

class TestParseAltFormatLine:
    @pytest.mark.parametrize("line,expected_ts_fragment", [
        ("2024/03/15 14:23:01 1.2.3.4 GET /api/users 200 142ms",    "2024-03-15"),
        ("15-Mar-2024 14:23:01 1.2.3.4 DELETE /api/x 200 300ms",    "2024-03-15"),
    ])
    def test_valid(self, line, expected_ts_fragment):
        e = parse_alt_format_line(line, 1)
        assert isinstance(e, Event)
        assert expected_ts_fragment in e.timestamp.isoformat()
        assert e.source_format == SourceFormat.ALTERNATE

    def test_lowercase_method_uppercased(self):
        e = parse_alt_format_line("2024/03/15 14:23:01 1.2.3.4 get /api 200 142ms", 1)
        assert isinstance(e, Event)
        assert e.method == "GET"

    def test_extra_tokens_captured(self):
        e = parse_alt_format_line(
            '2024/03/15 14:23:01 1.2.3.4 GET /api 200 142ms extra token', 1
        )
        assert isinstance(e, Event)
        assert e.raw_extra == "extra token"

    def test_path_not_normalized(self):
        # Deviation #7
        e = parse_alt_format_line("2024/03/15 14:23:01 1.2.3.4 GET /api/users/99 200 142ms", 1)
        assert isinstance(e, Event)
        assert e.path == "/api/users/99"

    def test_too_few_tokens_returns_none(self):
        assert parse_alt_format_line("2024/03/15 14:23:01 1.2.3.4 GET /api", 1) is None

    def test_non_alpha_method_returns_none(self):
        assert parse_alt_format_line("2024/03/15 14:23:01 1.2.3.4 192.168.1.1 /api 200 142ms", 1) is None

    def test_iso_two_token_combined_timestamp_invalid(self):
        # "2024-03-15T14:23:01Z" + " " + "192.168.1.42" doesn't normalize
        result = parse_alt_format_line("2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 142ms extra", 1)
        assert result is None

    def test_unclosed_quote_raises(self):
        from log_analyzer.parser import _UnclosedQuote
        with pytest.raises(_UnclosedQuote):
            parse_alt_format_line('2024/03/15 14:23:01 1.2.3.4 GET /api 200 142ms "unclosed', 1)


# ---------------------------------------------------------------------------
# Parser (full strategy chain)
# ---------------------------------------------------------------------------

class TestParser:
    def setup_method(self):
        self.parser = Parser()

    def test_blank_line(self):
        r = self.parser.parse("", 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.BLANK

    def test_whitespace_only(self):
        r = self.parser.parse("   \t  ", 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.BLANK

    @pytest.mark.parametrize("line", [
        "Traceback (most recent call last):",
        '  File "app.py", line 42, in handle_request',
        'File "db.py", line 17, in query',
        "Caused by: ConnectionRefusedError",
        "at com.example.Service.process(Service.java:101)",
    ])
    def test_stack_trace_lines(self, line):
        r = self.parser.parse(line, 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.STACK_TRACE_CONTINUATION

    def test_truncated_json_is_json_parse_error(self):
        r = self.parser.parse('{"timestamp":"2024-03-15T14:23:01Z","ip"', 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.JSON_PARSE_ERROR

    def test_unclosed_quote_in_alt_format(self):
        # This line fails STANDARD_RE (method position is an IP), then alt raises _UnclosedQuote
        r = self.parser.parse('2024/03/15 14:23:01 1.2.3.4 GET /api 200 142ms "unclosed', 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.UNCLOSED_QUOTE

    def test_garbage_line_is_unknown_format(self):
        r = self.parser.parse("---------", 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.UNKNOWN_FORMAT

    def test_standard_line_parses(self):
        r = self.parser.parse("2024-03-15T14:23:01Z 1.2.3.4 GET /api/users 200 142ms", 1)
        assert isinstance(r, Event)
        assert r.source_format == SourceFormat.STANDARD

    def test_json_line_parses(self):
        line = '{"timestamp":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"GET","path":"/api","status":200,"response_ms":10}'
        r = self.parser.parse(line, 1)
        assert isinstance(r, Event)
        assert r.source_format == SourceFormat.JSON

    def test_alt_format_line_parses(self):
        r = self.parser.parse("2024/03/15 14:23:01 1.2.3.4 GET /api/users 200 100ms", 1)
        assert isinstance(r, Event)
        assert r.source_format == SourceFormat.ALTERNATE

    def test_parser_error_swallowed_as_anomaly_when_not_debug(self):
        def crashing_strategy(line, line_no):
            raise RuntimeError("simulated parser bug")

        p = Parser(strategies=[crashing_strategy], debug=False)
        r = p.parse("any line here", 1)
        assert isinstance(r, Anomaly)
        assert r.kind == AnomalyKind.PARSER_ERROR
        assert "RuntimeError" in r.reason

    def test_parser_error_reraises_when_debug(self):
        def crashing_strategy(line, line_no):
            raise RuntimeError("simulated parser bug")

        p = Parser(strategies=[crashing_strategy], debug=True)
        with pytest.raises(RuntimeError, match="simulated parser bug"):
            p.parse("any line here", 1)

    def test_line_no_propagates(self):
        r = self.parser.parse("2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 10ms", 42)
        assert isinstance(r, Event)
        assert r.line_no == 42

    def test_leading_trailing_whitespace_stripped(self):
        r = self.parser.parse("  2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 10ms  ", 1)
        assert isinstance(r, Event)

    def test_json_preferred_over_standard(self):
        # A JSON line that could superficially look text-like — JSON strategy wins
        line = '{"timestamp":"2024-03-15T14:23:01Z","ip":"1.2.3.4","method":"GET","path":"/api","status":200,"response_ms":10}'
        r = self.parser.parse(line, 1)
        assert isinstance(r, Event)
        assert r.source_format == SourceFormat.JSON


# ---------------------------------------------------------------------------
# Stack trace prefix detection
# ---------------------------------------------------------------------------

class TestStackTraceDetection:
    @pytest.mark.parametrize("line,expected", [
        ("Traceback (most recent call last):",    True),
        ("at com.example.Service.process",         True),
        ('File "app.py", line 42',                 True),
        ("Caused by: SomeError",                   True),
        ("2024-03-15T14:23:01Z 1.2.3.4 GET /api 200 10ms", False),
        ("not a stack trace",                      False),
        ("",                                        False),
    ])
    def test_detection(self, line, expected):
        assert Parser._looks_like_stack_trace(line) == expected


# ---------------------------------------------------------------------------
# parse_extra_field utility
# ---------------------------------------------------------------------------

class TestParseExtraField:
    def test_none_returns_empty(self):
        assert parse_extra_field(None) == []

    def test_empty_string_returns_empty(self):
        assert parse_extra_field("") == []

    def test_quoted_token_split(self):
        tokens = parse_extra_field('"Mozilla/5.0 (Windows NT 10.0)"')
        assert tokens == ["Mozilla/5.0 (Windows NT 10.0)"]

    def test_multiple_tokens(self):
        tokens = parse_extra_field('"agent string" "http://referrer.com"')
        assert len(tokens) == 2

    def test_unclosed_quote_returns_raw(self):
        raw = '"unclosed quote'
        tokens = parse_extra_field(raw)
        assert tokens == [raw]


# ---------------------------------------------------------------------------
# Adversarial fixture — no crash, full coverage
# ---------------------------------------------------------------------------

class TestAdversarialFixture:
    def test_no_exception_escapes(self):
        parser = Parser()
        with open(FIXTURE, encoding="utf-8-sig", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                # Must not raise
                result = parser.parse(raw_line.rstrip("\n"), line_no)
                assert result is not None

    def test_every_line_produces_exactly_one_result(self):
        parser = Parser()
        results = []
        with open(FIXTURE, encoding="utf-8-sig", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                results.append(parser.parse(raw_line.rstrip("\n"), line_no))
        assert len(results) > 0

    def test_expected_anomaly_kinds_appear(self):
        parser = Parser()
        anomaly_kinds = set()
        with open(FIXTURE, encoding="utf-8-sig", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                result = parser.parse(raw_line.rstrip("\n"), line_no)
                if isinstance(result, Anomaly):
                    anomaly_kinds.add(result.kind)

        assert AnomalyKind.BLANK in anomaly_kinds
        assert AnomalyKind.STACK_TRACE_CONTINUATION in anomaly_kinds
        assert AnomalyKind.JSON_PARSE_ERROR in anomaly_kinds
        assert AnomalyKind.UNKNOWN_FORMAT in anomaly_kinds

    def test_some_events_parsed(self):
        parser = Parser()
        events = []
        with open(FIXTURE, encoding="utf-8-sig", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                result = parser.parse(raw_line.rstrip("\n"), line_no)
                if isinstance(result, Event):
                    events.append(result)
        assert len(events) > 0

    def test_lowercase_method_uppercased_in_fixture(self):
        parser = Parser()
        events = []
        with open(FIXTURE, encoding="utf-8-sig", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                result = parser.parse(raw_line.rstrip("\n"), line_no)
                if isinstance(result, Event):
                    events.append(result)
        # All methods on successfully parsed events should be uppercase
        for e in events:
            if e.method is not None:
                assert e.method == e.method.upper(), f"method not uppercased: {e.method!r} on line {e.line_no}"
