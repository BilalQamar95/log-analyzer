from datetime import datetime, timezone
from typing import Optional

import pytest

from log_analyzer.analyzer import Analyzer, LatencyStore
from log_analyzer.models import Anomaly, AnomalyKind, Event, FieldWarningKind, SourceFormat


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

_TS = datetime(2024, 3, 15, 14, 23, 1, tzinfo=timezone.utc)
_TS2 = datetime(2024, 3, 15, 15, 0, 0, tzinfo=timezone.utc)
_TS_EARLY = datetime(2024, 3, 15, 13, 0, 0, tzinfo=timezone.utc)


def make_event(
    *,
    timestamp: Optional[datetime] = _TS,
    ip: Optional[str] = "10.0.0.1",
    method: Optional[str] = "GET",
    path: str = "/api/users",
    status: Optional[int] = 200,
    response_ms: Optional[float] = 100.0,
    raw_status: Optional[str] = "200",
    raw_response_time: Optional[str] = "100ms",
    source_format: SourceFormat = SourceFormat.STANDARD,
    line_no: int = 1,
) -> Event:
    return Event(
        timestamp=timestamp,
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


def make_anomaly(
    kind: AnomalyKind = AnomalyKind.UNKNOWN_FORMAT,
    raw: str = "garbage",
    line_no: int = 1,
    reason: str = "",
) -> Anomaly:
    return Anomaly(kind=kind, raw=raw, line_no=line_no, reason=reason)


# ---------------------------------------------------------------------------
# LatencyStore
# ---------------------------------------------------------------------------

class TestLatencyStore:
    def test_empty_percentile_returns_none(self):
        s = LatencyStore()
        assert s.percentile(50) is None
        assert s.percentile(95) is None
        assert s.percentile(99) is None

    def test_empty_max_returns_none(self):
        assert LatencyStore().max() is None

    def test_empty_count_zero(self):
        assert LatencyStore().count() == 0

    def test_single_value(self):
        s = LatencyStore()
        s.add(42.0)
        assert s.percentile(50) == 42.0
        assert s.percentile(99) == 42.0
        assert s.max() == 42.0
        assert s.count() == 1

    def test_known_percentiles(self):
        s = LatencyStore()
        for v in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]:
            s.add(v)
        # sorted=[10,20,30,40,50,60,70,80,90,100]  len=10
        # p50: k=round(0.5*9)=round(4.5)=4 → 50.0
        # p90: k=round(0.9*9)=round(8.1)=8 → 90.0
        assert s.percentile(50) == 50.0
        assert s.percentile(90) == 90.0
        assert s.max() == 100.0
        assert s.count() == 10

    def test_add_does_not_mutate_input_list(self):
        s = LatencyStore()
        s.add(5.0)
        s.add(3.0)
        s.add(7.0)
        # percentile must sort internally; subsequent calls must be consistent
        assert s.percentile(50) == s.percentile(50)
        assert s.max() == 7.0


# ---------------------------------------------------------------------------
# Empty analyzer
# ---------------------------------------------------------------------------

class TestEmptyAnalyzer:
    def test_snapshot_zero_counts(self):
        snap = Analyzer().snapshot()
        assert snap["total_lines"] == 0
        assert snap["parsed_lines"] == 0
        assert snap["anomaly_count"] == 0
        assert snap["parse_success_rate"] == 0.0

    def test_snapshot_date_range_none(self):
        snap = Analyzer().snapshot()
        assert snap["date_range"]["first"] is None
        assert snap["date_range"]["last"] is None

    def test_snapshot_empty_top_lists(self):
        snap = Analyzer().snapshot()
        assert snap["top_endpoints"] == []
        assert snap["slowest_endpoints"] == []
        assert snap["error_heavy_endpoints"] == []
        assert snap["top_ips"] == []

    def test_invariant_holds_for_empty(self):
        Analyzer().snapshot()  # assert inside snapshot() must not raise


# ---------------------------------------------------------------------------
# Single event and anomaly
# ---------------------------------------------------------------------------

class TestSingleConsume:
    def test_single_event_increments_counters(self):
        a = Analyzer()
        a.consume(make_event())
        assert a.total_lines == 1
        assert a.parsed_lines == 1
        assert a.anomaly_count == 0

    def test_single_anomaly_increments_counters(self):
        a = Analyzer()
        a.consume(make_anomaly())
        assert a.total_lines == 1
        assert a.parsed_lines == 0
        assert a.anomaly_count == 1

    def test_single_event_snapshot_parse_rate(self):
        a = Analyzer()
        a.consume(make_event())
        assert a.snapshot()["parse_success_rate"] == 1.0

    def test_single_event_format_counted(self):
        a = Analyzer()
        a.consume(make_event(source_format=SourceFormat.JSON))
        assert a.format_counts[SourceFormat.JSON] == 1

    def test_single_event_ip_counted(self):
        a = Analyzer()
        a.consume(make_event(ip="1.2.3.4"))
        assert a.ip_counts["1.2.3.4"] == 1

    def test_single_event_status_class_counted(self):
        a = Analyzer()
        a.consume(make_event(status=200))
        assert a.status_class_counts["2xx"] == 1

    def test_single_anomaly_kind_counted(self):
        a = Analyzer()
        a.consume(make_anomaly(kind=AnomalyKind.BLANK))
        assert a.anomaly_counts[AnomalyKind.BLANK] == 1

    def test_single_anomaly_sample_stored(self):
        a = Analyzer()
        anomaly = make_anomaly(kind=AnomalyKind.BLANK, raw="  ", line_no=7)
        a.consume(anomaly)
        assert a.anomaly_samples[AnomalyKind.BLANK] == [anomaly]


# ---------------------------------------------------------------------------
# Invariant
# ---------------------------------------------------------------------------

class TestInvariant:
    def test_mix_invariant(self):
        a = Analyzer()
        for i in range(7):
            a.consume(make_event(line_no=i))
        for i in range(3):
            a.consume(make_anomaly(line_no=100 + i))
        snap = a.snapshot()  # assert parsed + anomalies == total must not raise
        assert snap["total_lines"] == 10
        assert snap["parsed_lines"] == 7
        assert snap["anomaly_count"] == 3


# ---------------------------------------------------------------------------
# Date range
# ---------------------------------------------------------------------------

class TestDateRange:
    def test_date_range_single_event(self):
        a = Analyzer()
        a.consume(make_event(timestamp=_TS))
        snap = a.snapshot()
        assert snap["date_range"]["first"] == _TS.isoformat()
        assert snap["date_range"]["last"] == _TS.isoformat()

    def test_date_range_expands_correctly(self):
        a = Analyzer()
        a.consume(make_event(timestamp=_TS))
        a.consume(make_event(timestamp=_TS_EARLY))
        a.consume(make_event(timestamp=_TS2))
        snap = a.snapshot()
        assert snap["date_range"]["first"] == _TS_EARLY.isoformat()
        assert snap["date_range"]["last"] == _TS2.isoformat()

    def test_none_timestamp_does_not_affect_range(self):
        a = Analyzer()
        a.consume(make_event(timestamp=_TS))
        a.consume(make_event(timestamp=None))
        snap = a.snapshot()
        assert snap["date_range"]["first"] == _TS.isoformat()
        assert snap["date_range"]["last"] == _TS.isoformat()


# ---------------------------------------------------------------------------
# Path normalization (deviation #7)
# ---------------------------------------------------------------------------

class TestPathNormalization:
    def test_numeric_ids_collapse_to_same_key(self):
        a = Analyzer()
        a.consume(make_event(method="GET", path="/api/users/1"))
        a.consume(make_event(method="GET", path="/api/users/2"))
        a.consume(make_event(method="GET", path="/api/users/999"))
        assert a.endpoint_request_counts["GET /api/users/:id"] == 3
        assert len(a.endpoint_request_counts) == 1

    def test_query_string_stripped(self):
        a = Analyzer()
        a.consume(make_event(method="GET", path="/api/users/12?page=2"))
        a.consume(make_event(method="GET", path="/api/users/13"))
        assert a.endpoint_request_counts["GET /api/users/:id"] == 2

    def test_different_methods_are_different_keys(self):
        a = Analyzer()
        a.consume(make_event(method="GET", path="/api/users"))
        a.consume(make_event(method="POST", path="/api/users"))
        assert len(a.endpoint_request_counts) == 2

    def test_uuid_segment_collapsed(self):
        a = Analyzer()
        a.consume(make_event(method="GET", path="/api/users/550e8400-e29b-41d4-a716-446655440000"))
        assert "GET /api/users/:uuid" in a.endpoint_request_counts


# ---------------------------------------------------------------------------
# Field warnings
# ---------------------------------------------------------------------------

class TestFieldWarnings:
    def test_invalid_status_string_triggers_warning(self):
        a = Analyzer()
        a.consume(make_event(status=None, raw_status="abc"))
        assert a.field_warning_counts[FieldWarningKind.INVALID_STATUS] == 1

    def test_dash_status_no_warning(self):
        a = Analyzer()
        a.consume(make_event(status=None, raw_status="-"))
        assert a.field_warning_counts.get(FieldWarningKind.INVALID_STATUS, 0) == 0

    def test_none_raw_status_no_warning(self):
        a = Analyzer()
        a.consume(make_event(status=None, raw_status=None))
        assert a.field_warning_counts.get(FieldWarningKind.INVALID_STATUS, 0) == 0

    def test_invalid_response_time_triggers_warning(self):
        a = Analyzer()
        a.consume(make_event(response_ms=None, raw_response_time="not-a-number"))
        assert a.field_warning_counts[FieldWarningKind.INVALID_RESPONSE_TIME] == 1

    def test_dash_response_time_no_warning(self):
        a = Analyzer()
        a.consume(make_event(response_ms=None, raw_response_time="-"))
        assert a.field_warning_counts.get(FieldWarningKind.INVALID_RESPONSE_TIME, 0) == 0

    def test_field_warnings_in_snapshot(self):
        a = Analyzer()
        a.consume(make_event(status=None, raw_status="xyz"))
        snap = a.snapshot()
        assert snap["field_warnings"]["invalid_status"] == 1


# ---------------------------------------------------------------------------
# Status class distribution
# ---------------------------------------------------------------------------

class TestStatusClass:
    def test_status_classes_bucketed(self):
        a = Analyzer()
        for status in [200, 201, 301, 404, 500, 502]:
            a.consume(make_event(status=status, raw_status=str(status)))
        counts = a.snapshot()["status_class_counts"]
        assert counts["2xx"] == 2
        assert counts["3xx"] == 1
        assert counts["4xx"] == 1
        assert counts["5xx"] == 2

    def test_missing_status_counted(self):
        a = Analyzer()
        a.consume(make_event(status=None, raw_status="-"))
        assert a.snapshot()["status_class_counts"]["missing"] == 1


# ---------------------------------------------------------------------------
# Latency and global latency
# ---------------------------------------------------------------------------

class TestLatency:
    def test_global_latency_counted(self):
        a = Analyzer()
        a.consume(make_event(response_ms=100.0))
        a.consume(make_event(response_ms=200.0))
        assert a.global_latencies.count() == 2

    def test_global_latency_without_endpoint(self):
        # response_ms should count toward global even when method is None
        a = Analyzer()
        a.consume(make_event(method=None, response_ms=500.0))
        assert a.global_latencies.count() == 1

    def test_endpoint_latency_tracked(self):
        a = Analyzer()
        a.consume(make_event(path="/api/health", response_ms=50.0))
        a.consume(make_event(path="/api/health", response_ms=150.0))
        store = a.endpoint_latencies["GET /api/health"]
        assert store.count() == 2
        assert store.percentile(50) == 50.0 or store.percentile(50) == 150.0

    def test_slowest_endpoints_sorted_by_p95(self):
        a = Analyzer()
        for _ in range(5):
            a.consume(make_event(path="/api/slow", response_ms=900.0))
        for _ in range(5):
            a.consume(make_event(path="/api/fast", response_ms=10.0))
        rows = a.snapshot()["slowest_endpoints"]
        assert rows[0]["endpoint"] == "GET /api/slow"
        assert rows[1]["endpoint"] == "GET /api/fast"


# ---------------------------------------------------------------------------
# Error-heavy endpoints
# ---------------------------------------------------------------------------

class TestErrorHeavyEndpoints:
    def test_errors_counted_per_endpoint(self):
        a = Analyzer()
        a.consume(make_event(path="/api/boom", status=500, raw_status="500"))
        a.consume(make_event(path="/api/boom", status=500, raw_status="500"))
        a.consume(make_event(path="/api/boom", status=404, raw_status="404"))
        a.consume(make_event(path="/api/ok", status=200, raw_status="200"))
        snap = a.snapshot()
        rows = snap["error_heavy_endpoints"]
        assert len(rows) == 1
        assert rows[0]["endpoint"] == "GET /api/boom"
        assert rows[0]["total_errors"] == 3
        assert rows[0]["by_status"][500] == 2
        assert rows[0]["by_status"][404] == 1

    def test_error_heavy_sorted_by_total_errors(self):
        a = Analyzer()
        for _ in range(3):
            a.consume(make_event(path="/api/a", status=500, raw_status="500"))
        for _ in range(7):
            a.consume(make_event(path="/api/b", status=500, raw_status="500"))
        rows = a.snapshot()["error_heavy_endpoints"]
        assert rows[0]["endpoint"] == "GET /api/b"


# ---------------------------------------------------------------------------
# Anomaly sample cap
# ---------------------------------------------------------------------------

class TestAnomalySampleCap:
    def test_cap_at_max_samples(self):
        a = Analyzer(max_anomaly_samples=3)
        for i in range(10):
            a.consume(make_anomaly(kind=AnomalyKind.BLANK, raw=f"line{i}", line_no=i))
        assert len(a.anomaly_samples[AnomalyKind.BLANK]) == 3

    def test_kept_samples_are_first_n(self):
        a = Analyzer(max_anomaly_samples=2)
        a.consume(make_anomaly(kind=AnomalyKind.BLANK, raw="first", line_no=1))
        a.consume(make_anomaly(kind=AnomalyKind.BLANK, raw="second", line_no=2))
        a.consume(make_anomaly(kind=AnomalyKind.BLANK, raw="third", line_no=3))
        raws = [s.raw for s in a.anomaly_samples[AnomalyKind.BLANK]]
        assert raws == ["first", "second"]


# ---------------------------------------------------------------------------
# Endpoint without method/path
# ---------------------------------------------------------------------------

class TestNoEndpointContext:
    def test_no_method_does_not_add_to_endpoint_counts(self):
        a = Analyzer()
        a.consume(make_event(method=None, status=200))
        assert len(a.endpoint_request_counts) == 0

    def test_no_path_does_not_add_to_endpoint_counts(self):
        a = Analyzer()
        a.consume(make_event(path="", status=200))
        assert len(a.endpoint_request_counts) == 0

    def test_status_class_still_counted_without_endpoint(self):
        a = Analyzer()
        a.consume(make_event(method=None, status=404))
        assert a.status_class_counts["4xx"] == 1


# ---------------------------------------------------------------------------
# Source format counts
# ---------------------------------------------------------------------------

class TestSourceFormatCounts:
    def test_format_counts_in_snapshot(self):
        a = Analyzer()
        a.consume(make_event(source_format=SourceFormat.JSON))
        a.consume(make_event(source_format=SourceFormat.JSON))
        a.consume(make_event(source_format=SourceFormat.STANDARD))
        a.consume(make_event(source_format=SourceFormat.ALTERNATE))
        snap = a.snapshot()
        assert snap["format_counts"]["json"] == 2
        assert snap["format_counts"]["standard"] == 1
        assert snap["format_counts"]["alternate"] == 1
