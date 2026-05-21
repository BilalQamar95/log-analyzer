import argparse
import io
import json
from datetime import datetime, timezone
from typing import Optional

import pytest

from log_analyzer.analyzer import Analyzer
from log_analyzer.models import Anomaly, AnomalyKind, Event, FieldWarningKind, SourceFormat
from log_analyzer.reporter import JsonReporter, TextReporter


# ---------------------------------------------------------------------------
# Factories (local copies to avoid cross-test-module imports)
# ---------------------------------------------------------------------------

_TS = datetime(2024, 3, 15, 14, 23, 1, tzinfo=timezone.utc)


def make_event(
    *,
    path: str = "/api/users",
    method: Optional[str] = "GET",
    status: Optional[int] = 200,
    response_ms: Optional[float] = 100.0,
    raw_status: Optional[str] = "200",
    raw_response_time: Optional[str] = "100ms",
    ip: str = "10.0.0.1",
    source_format: SourceFormat = SourceFormat.STANDARD,
    line_no: int = 1,
) -> Event:
    return Event(
        timestamp=_TS,
        ip=ip,
        method=method,
        path=path,
        raw_path=path,
        status=status,
        response_ms=response_ms,
        raw_status=raw_status,
        raw_response_time=raw_response_time,
        source_format=source_format,
        line_no=line_no,
    )


def make_anomaly(kind: AnomalyKind = AnomalyKind.BLANK, raw: str = "", line_no: int = 1) -> Anomaly:
    return Anomaly(kind=kind, raw=raw, line_no=line_no, reason="")


def make_args(**kwargs) -> argparse.Namespace:
    defaults = dict(path="test.log", slowest=None, errors=False, anomalies=False, status=None, json=False)
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def render(snapshot, **kwargs) -> str:
    out = io.StringIO()
    TextReporter().render(snapshot, make_args(**kwargs), out)
    return out.getvalue()


def empty_snapshot():
    return Analyzer().snapshot()


def basic_snapshot():
    a = Analyzer()
    for _ in range(5):
        a.consume(make_event(path="/api/fast", response_ms=50.0))
    for _ in range(3):
        a.consume(make_event(path="/api/slow", response_ms=900.0))
    for _ in range(2):
        a.consume(make_event(path="/api/boom", status=500, raw_status="500", response_ms=200.0))
    a.consume(make_event(path="/api/boom", status=404, raw_status="404"))
    a.consume(make_event(source_format=SourceFormat.JSON))
    a.consume(make_anomaly(kind=AnomalyKind.BLANK, raw="   "))
    a.consume(make_anomaly(kind=AnomalyKind.UNKNOWN_FORMAT, raw="garbage"))
    return a.snapshot()


# ---------------------------------------------------------------------------
# JsonReporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def test_output_is_valid_json(self):
        out = io.StringIO()
        JsonReporter().render(empty_snapshot(), make_args(), out)
        data = json.loads(out.getvalue())
        assert isinstance(data, dict)

    def test_preserves_all_top_level_keys(self):
        out = io.StringIO()
        JsonReporter().render(empty_snapshot(), make_args(), out)
        data = json.loads(out.getvalue())
        for key in ("total_lines", "parsed_lines", "anomaly_count", "parse_success_rate",
                    "format_counts", "status_class_counts", "top_endpoints", "top_ips",
                    "date_range", "global_latency", "anomalies", "field_warnings"):
            assert key in data

    def test_ends_with_newline(self):
        out = io.StringIO()
        JsonReporter().render(empty_snapshot(), make_args(), out)
        assert out.getvalue().endswith("\n")


# ---------------------------------------------------------------------------
# TextReporter default mode — section presence
# ---------------------------------------------------------------------------

class TestTextReporterDefaultSections:
    def test_all_sections_present(self):
        text = render(basic_snapshot())
        for heading in (
            "Log Analyzer Report",
            "Summary",
            "Format breakdown",
            "Date range",
            "Status summary",
            "Global latency",
            "Top endpoints",
            "Slowest endpoints",
            "Error-heavy endpoints",
            "Top IPs",
            "Field warnings",
            "Anomalies",
        ):
            assert heading in text, f"missing: {heading!r}"

    def test_header_shows_path(self):
        text = render(basic_snapshot(), path="/var/log/app.log")
        assert "Input: /var/log/app.log" in text

    def test_section_order(self):
        text = render(basic_snapshot())
        # Use unique substrings that appear only in section headings, not in data rows.
        # "Anomalies" also appears in Summary as "Anomalies:  N", so use the full heading.
        positions = [
            text.index("Summary"),
            text.index("Format breakdown"),
            text.index("Date range"),
            text.index("Status summary"),
            text.index("Global latency"),
            text.index("Top endpoints by traffic"),
            text.index("Slowest endpoints by p95"),
            text.index("Error-heavy endpoints:"),
            text.index("Top IPs:"),
            text.index("Field warnings"),
            text.index("Anomalies (lines skipped)"),
        ]
        assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# TextReporter — empty snapshot
# ---------------------------------------------------------------------------

class TestTextReporterEmpty:
    def test_empty_snapshot_does_not_crash(self):
        render(empty_snapshot())  # must not raise

    def test_empty_has_no_data_markers(self):
        text = render(empty_snapshot())
        assert "(no data)" in text or "(none)" in text

    def test_empty_date_range_message(self):
        text = render(empty_snapshot())
        assert "no events with valid timestamps" in text


# ---------------------------------------------------------------------------
# --slowest deviation #3
# ---------------------------------------------------------------------------

class TestSlowestFlag:
    def _make_snapshot_with_n_slow_endpoints(self, n):
        a = Analyzer()
        for i in range(n):
            for _ in range(5):
                a.consume(make_event(path=f"/api/ep{i}", response_ms=float(100 + i * 10)))
        return a.snapshot()

    def test_slowest_default_10(self):
        snap = self._make_snapshot_with_n_slow_endpoints(12)
        text = render(snap)
        assert "top 10" in text

    def test_slowest_zero_produces_empty_section(self):
        snap = self._make_snapshot_with_n_slow_endpoints(5)
        text = render(snap, slowest=0)
        assert "top 0" in text
        assert "(no data)" in text

    def test_slowest_5_shows_top_5(self):
        snap = self._make_snapshot_with_n_slow_endpoints(10)
        text = render(snap, slowest=5)
        assert "top 5" in text

    def test_slowest_negative_clamped_to_zero(self):
        snap = self._make_snapshot_with_n_slow_endpoints(5)
        text = render(snap, slowest=-3)
        assert "(no data)" in text  # clamped to 0, no endpoints shown


# ---------------------------------------------------------------------------
# Section gating flags
# ---------------------------------------------------------------------------

class TestSectionGating:
    def test_errors_flag_shows_only_errors(self):
        text = render(basic_snapshot(), errors=True)
        assert "Error-heavy endpoints" in text
        assert "Summary" not in text
        assert "Format breakdown" not in text

    def test_anomalies_flag_shows_only_anomalies(self):
        text = render(basic_snapshot(), anomalies=True)
        assert "Anomalies" in text
        assert "Summary" not in text
        assert "Top endpoints" not in text

    def test_status_flag_shows_only_status_section(self):
        a = Analyzer()
        a.consume(make_event(path="/api/boom", status=500, raw_status="500"))
        text = render(a.snapshot(), status="5xx")
        assert "Status filter" in text
        assert "Summary" not in text


# ---------------------------------------------------------------------------
# None percentiles render as "-"
# ---------------------------------------------------------------------------

class TestNoneFormatting:
    def test_none_percentile_renders_as_dash(self):
        a = Analyzer()
        a.consume(make_event(response_ms=None, raw_response_time="-"))
        text = render(a.snapshot())
        assert "Nonems" not in text
        assert "(no data)" in text  # global latency section


# ---------------------------------------------------------------------------
# Status filter
# ---------------------------------------------------------------------------

class TestStatusFilter:
    def _snapshot_with_errors(self):
        a = Analyzer()
        a.consume(make_event(path="/api/boom", status=500, raw_status="500"))
        a.consume(make_event(path="/api/boom", status=503, raw_status="503"))
        a.consume(make_event(path="/api/notfound", status=404, raw_status="404"))
        a.consume(make_event(path="/api/ok", status=200, raw_status="200"))
        return a.snapshot()

    def test_exact_code_filter_500(self):
        text = render(self._snapshot_with_errors(), status="500")
        assert "Status filter: 500" in text
        assert "5xx" in text
        assert "/api/boom" in text
        assert "/api/notfound" not in text  # 404, not 500

    def test_class_filter_5xx(self):
        text = render(self._snapshot_with_errors(), status="5xx")
        assert "Status filter: 5xx" in text
        assert "/api/boom" in text

    def test_class_filter_4xx(self):
        text = render(self._snapshot_with_errors(), status="4xx")
        assert "Status filter: 4xx" in text
        assert "/api/notfound" in text
        assert "/api/boom" not in text  # only 5xx errors

    def test_invalid_status_writes_error_line(self):
        a = Analyzer()
        a.consume(make_event())
        text = render(a.snapshot(), status="garbage")
        assert "error: invalid status filter 'garbage'" in text

    def test_no_matching_endpoints(self):
        a = Analyzer()
        a.consume(make_event(path="/api/ok", status=200))
        text = render(a.snapshot(), status="5xx")
        assert "no matching endpoints" in text


# ---------------------------------------------------------------------------
# Anomaly samples
# ---------------------------------------------------------------------------

class TestAnomalySamples:
    def test_default_shows_samples(self):
        a = Analyzer()
        for i in range(5):
            a.consume(make_anomaly(kind=AnomalyKind.UNKNOWN_FORMAT, raw=f"bad line {i}", line_no=i))
        text = render(a.snapshot())
        assert "Sample unknown_format" in text

    def test_anomalies_flag_shows_full_samples(self):
        a = Analyzer(max_anomaly_samples=10)
        for i in range(10):
            a.consume(make_anomaly(kind=AnomalyKind.UNKNOWN_FORMAT, raw=f"bad {i}", line_no=i))
        text = render(a.snapshot(), anomalies=True)
        assert "bad 9" in text  # 10 fed == cap, so all are stored (first-N policy)
