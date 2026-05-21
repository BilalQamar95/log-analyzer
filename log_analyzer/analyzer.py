from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from log_analyzer.models import Anomaly, AnomalyKind, Event, FieldWarningKind, ParseResult, SourceFormat
from log_analyzer.normalizers import normalize_path, status_class


class LatencyStore:
    """Accumulates response-time samples for exact percentile queries."""

    def __init__(self) -> None:
        self._samples: List[float] = []

    def add(self, value: float) -> None:
        self._samples.append(value)

    def percentile(self, p: float) -> Optional[float]:
        if not self._samples:
            return None
        sorted_samples = sorted(self._samples)
        k = int(round((p / 100.0) * (len(sorted_samples) - 1)))
        return sorted_samples[k]

    def max(self) -> Optional[float]:
        return max(self._samples) if self._samples else None

    def count(self) -> int:
        return len(self._samples)


class Analyzer:
    """Streaming aggregator. Feed ParseResult objects one at a time; call snapshot() when done."""

    def __init__(self, max_anomaly_samples: int = 5) -> None:
        self.total_lines = 0
        self.parsed_lines = 0
        self.anomaly_count = 0

        self.format_counts: Counter[SourceFormat] = Counter()
        self.status_class_counts: Counter[str] = Counter()
        self.endpoint_request_counts: Counter[str] = Counter()
        self.endpoint_error_counts: Dict[str, Counter[int]] = defaultdict(Counter)
        self.endpoint_latencies: Dict[str, LatencyStore] = defaultdict(LatencyStore)
        self.global_latencies: LatencyStore = LatencyStore()
        self.ip_counts: Counter[str] = Counter()

        self.first_timestamp: Optional[datetime] = None
        self.last_timestamp: Optional[datetime] = None

        self.anomaly_counts: Counter[AnomalyKind] = Counter()
        self.anomaly_samples: Dict[AnomalyKind, List[Anomaly]] = defaultdict(list)
        self._max_samples = max_anomaly_samples

        self.field_warning_counts: Counter[FieldWarningKind] = Counter()

    def consume(self, result: ParseResult) -> None:
        self.total_lines += 1
        if isinstance(result, Anomaly):
            self._consume_anomaly(result)
        else:
            self._consume_event(result)

    def _consume_anomaly(self, a: Anomaly) -> None:
        self.anomaly_count += 1
        self.anomaly_counts[a.kind] += 1
        samples = self.anomaly_samples[a.kind]
        if len(samples) < self._max_samples:
            samples.append(a)

    def _consume_event(self, e: Event) -> None:
        self.parsed_lines += 1
        self.format_counts[e.source_format] += 1

        if e.timestamp is not None:
            if self.first_timestamp is None or e.timestamp < self.first_timestamp:
                self.first_timestamp = e.timestamp
            if self.last_timestamp is None or e.timestamp > self.last_timestamp:
                self.last_timestamp = e.timestamp

        self.status_class_counts[status_class(e.status)] += 1

        # Field warnings: field validity is independent of endpoint attribution
        if e.status is None and e.raw_status not in (None, "-", ""):
            self.field_warning_counts[FieldWarningKind.INVALID_STATUS] += 1
        if e.response_ms is None and e.raw_response_time not in (None, "-", ""):
            self.field_warning_counts[FieldWarningKind.INVALID_RESPONSE_TIME] += 1

        # Global latency: counts whenever present, even without endpoint context
        if e.response_ms is not None:
            self.global_latencies.add(e.response_ms)

        if e.method and e.path:
            endpoint_key = f"{e.method} {normalize_path(e.path)}"  # deviation #7
            self.endpoint_request_counts[endpoint_key] += 1
            if e.status is not None and e.status >= 400:
                self.endpoint_error_counts[endpoint_key][e.status] += 1
            if e.response_ms is not None:
                self.endpoint_latencies[endpoint_key].add(e.response_ms)

        if e.ip:
            self.ip_counts[e.ip] += 1

    def snapshot(self) -> Dict[str, Any]:
        assert self.parsed_lines + self.anomaly_count == self.total_lines  # deviation #8

        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "anomaly_count": self.anomaly_count,
            "parse_success_rate": (
                self.parsed_lines / self.total_lines if self.total_lines else 0.0
            ),
            "format_counts": {k.value: v for k, v in self.format_counts.items()},
            "status_class_counts": dict(self.status_class_counts),
            "top_endpoints": self.endpoint_request_counts.most_common(10),
            "slowest_endpoints": self._slowest_endpoints(10),
            "error_heavy_endpoints": self._error_heavy_endpoints(10),
            "top_ips": self.ip_counts.most_common(10),
            "date_range": {
                "first": self.first_timestamp.isoformat() if self.first_timestamp else None,
                "last": self.last_timestamp.isoformat() if self.last_timestamp else None,
            },
            "global_latency": {
                "count": self.global_latencies.count(),
                "p50": self.global_latencies.percentile(50),
                "p95": self.global_latencies.percentile(95),
                "p99": self.global_latencies.percentile(99),
                "max": self.global_latencies.max(),
            },
            "anomalies": {
                "counts": {k.value: v for k, v in self.anomaly_counts.items()},
                "samples": {
                    k.value: [
                        {"line_no": a.line_no, "raw": a.raw[:200], "reason": a.reason}
                        for a in v
                    ]
                    for k, v in self.anomaly_samples.items()
                },
            },
            "field_warnings": {k.value: v for k, v in self.field_warning_counts.items()},
        }

    def _slowest_endpoints(self, n: int) -> List[Dict[str, Any]]:
        rows = []
        for endpoint, store in self.endpoint_latencies.items():
            if store.count() == 0:
                continue
            rows.append({
                "endpoint": endpoint,
                "count": store.count(),
                "p95": store.percentile(95),
                "p99": store.percentile(99),
                "max": store.max(),
            })
        rows.sort(key=lambda r: r["p95"] or 0, reverse=True)
        return rows[:n]

    def _error_heavy_endpoints(self, n: int) -> List[Dict[str, Any]]:
        rows = []
        for endpoint, status_counter in self.endpoint_error_counts.items():
            total_errors = sum(status_counter.values())
            if total_errors == 0:
                continue
            rows.append({
                "endpoint": endpoint,
                "total_errors": total_errors,
                "by_status": dict(status_counter),
            })
        rows.sort(key=lambda r: r["total_errors"], reverse=True)
        return rows[:n]
