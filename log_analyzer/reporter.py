import json
from typing import Any, Dict


def _fmt_ms(v) -> str:
    return f"{int(v)}ms" if v is not None else "-"


class JsonReporter:
    def render(self, snapshot: Dict[str, Any], args: Any, output: Any) -> None:
        json.dump(snapshot, output, indent=2, default=str)
        output.write("\n")


class TextReporter:
    def render(self, snapshot: Dict[str, Any], args: Any, output: Any) -> None:
        w = lambda s: output.write(s + "\n")
        show_all = not (args.errors or args.anomalies or args.status)

        if show_all:
            self._render_header(snapshot, args, w)
            self._render_summary(snapshot, w)
            self._render_format_breakdown(snapshot, w)
            self._render_date_range(snapshot, w)
            self._render_status_summary(snapshot, w)
            self._render_global_latency(snapshot, w)
            self._render_top_endpoints(snapshot, w)
            n = args.slowest if args.slowest is not None else 10  # deviation #3
            self._render_slowest(snapshot, max(0, n), w)
            self._render_error_heavy(snapshot, w)
            self._render_top_ips(snapshot, w)
            self._render_field_warnings(snapshot, w)
            self._render_anomalies(snapshot, w)
        elif args.anomalies:
            self._render_header(snapshot, args, w)
            self._render_anomalies(snapshot, w, full=True)
        elif args.errors:
            self._render_header(snapshot, args, w)
            self._render_error_heavy(snapshot, w)
        elif args.status:
            self._render_header(snapshot, args, w)
            self._render_status_filter(snapshot, args.status, w)

    @staticmethod
    def _render_header(snapshot, args, w):
        w("Log Analyzer Report")
        w("===================")
        w(f"Input: {args.path}")
        w("")

    @staticmethod
    def _render_summary(snapshot, w):
        w("Summary")
        w("-------")
        w(f"Total lines:  {snapshot['total_lines']:>8}")
        w(f"Parsed:       {snapshot['parsed_lines']:>8}  ({snapshot['parse_success_rate']:.2%})")
        w(f"Anomalies:    {snapshot['anomaly_count']:>8}")
        w("")

    @staticmethod
    def _render_format_breakdown(snapshot, w):
        counts = snapshot["format_counts"]
        if not counts:
            return
        w("Format breakdown:")
        for fmt, count in sorted(counts.items()):
            w(f"  {fmt + ':':<16}{count:>8}")
        w("")

    @staticmethod
    def _render_date_range(snapshot, w):
        dr = snapshot["date_range"]
        w("Date range:")
        if dr["first"] and dr["last"]:
            w(f"  {dr['first']} → {dr['last']}")
        else:
            w("  no events with valid timestamps")
        w("")

    @staticmethod
    def _render_status_summary(snapshot, w):
        counts = snapshot["status_class_counts"]
        w("Status summary:")
        any_data = False
        for cls in ("2xx", "3xx", "4xx", "5xx", "missing"):
            n = counts.get(cls, 0)
            if n:
                w(f"  {cls + ':':<12}{n:>8}")
                any_data = True
        if not any_data:
            w("  (no data)")
        w("")

    @staticmethod
    def _render_global_latency(snapshot, w):
        gl = snapshot["global_latency"]
        count = gl["count"]
        w(f"Global latency ({count} events with valid latency):")
        if count == 0:
            w("  (no data)")
        else:
            w(f"  p50:  {_fmt_ms(gl['p50'])}")
            w(f"  p95:  {_fmt_ms(gl['p95'])}")
            w(f"  p99:  {_fmt_ms(gl['p99'])}")
            w(f"  max:  {_fmt_ms(gl['max'])}")
        w("")

    @staticmethod
    def _render_top_endpoints(snapshot, w):
        rows = snapshot["top_endpoints"]
        w("Top endpoints by traffic:")
        if not rows:
            w("  (no data)")
        else:
            for endpoint, count in rows:
                w(f"  {endpoint:<34}{count:>8}")
        w("")

    @staticmethod
    def _render_slowest(snapshot, n, w):
        rows = snapshot["slowest_endpoints"][:n]
        w(f"Slowest endpoints by p95 (top {n}):")
        if not rows:
            w("  (no data)")
        else:
            for r in rows:
                w(
                    f"  {r['endpoint']:<34}"
                    f"  p95={_fmt_ms(r['p95']):<10}"
                    f"  p99={_fmt_ms(r['p99']):<10}"
                    f"  count={r['count']}"
                )
        w("")

    @staticmethod
    def _render_error_heavy(snapshot, w):
        rows = snapshot["error_heavy_endpoints"]
        w("Error-heavy endpoints:")
        if not rows:
            w("  (no data)")
        else:
            for r in rows:
                by = "  ".join(
                    f"{code}={cnt}"
                    for code, cnt in sorted(r["by_status"].items(), key=lambda x: -x[1])
                )
                w(f"  {r['endpoint']:<34}  total={r['total_errors']:<6}  {by}")
        w("")

    @staticmethod
    def _render_top_ips(snapshot, w):
        rows = snapshot["top_ips"]
        w("Top IPs:")
        if not rows:
            w("  (no data)")
        else:
            for ip, count in rows:
                w(f"  {ip:<26}{count:>8}")
        w("")

    @staticmethod
    def _render_field_warnings(snapshot, w):
        warnings = snapshot["field_warnings"]
        w("Field warnings (line parsed but field was invalid):")
        if not warnings:
            w("  (none)")
        else:
            for kind, count in sorted(warnings.items()):
                w(f"  {kind + ':':<30}{count:>6}")
        w("")

    @staticmethod
    def _render_anomalies(snapshot, w, full=False):
        anom = snapshot["anomalies"]
        counts = anom["counts"]
        samples = anom["samples"]
        w("Anomalies (lines skipped):")
        if not counts:
            w("  (none)")
            w("")
            return
        for kind, count in sorted(counts.items(), key=lambda x: -x[1]):
            w(f"  {kind + ':':<30}{count:>6}")
        w("")
        for kind, sample_list in samples.items():
            if not sample_list:
                continue
            show = sample_list if full else sample_list[:3]
            label = f"Sample {kind} lines" + ("" if full else f" (first {len(show)})")
            w(f"  {label}:")
            for s in show:
                raw_display = s["raw"][:80].replace("\n", "\\n")
                reason = f"  [{s['reason']}]" if s.get("reason") else ""
                w(f"    line {s['line_no']:>5}: {raw_display!r}{reason}")
        w("")

    @staticmethod
    def _render_status_filter(snapshot, status_str, w):
        exact_code = None
        cls = None

        if status_str.isdigit():
            exact_code = int(status_str)
            prefix = str(exact_code)[0]
            cls = {"2": "2xx", "3": "3xx", "4": "4xx", "5": "5xx"}.get(prefix)
        elif (
            len(status_str) == 3
            and status_str[1:].lower() == "xx"
            and status_str[0].isdigit()
        ):
            cls = status_str.lower()
        else:
            w(f"error: invalid status filter '{status_str}'")
            return

        w(f"Status filter: {status_str}")
        if cls:
            w(f"  {cls}: {snapshot['status_class_counts'].get(cls, 0)}")
        w("")

        cls_digit = cls[0] if cls else (str(exact_code)[0] if exact_code else None)
        error_heavy = snapshot["error_heavy_endpoints"]

        if exact_code is not None:
            matching = [r for r in error_heavy if exact_code in r["by_status"]]
        elif cls_digit:
            matching = [
                r for r in error_heavy
                if any(str(code)[0] == cls_digit for code in r["by_status"])
            ]
        else:
            matching = []

        if not matching:
            w("  (no matching endpoints)")
            return

        w(f"Error-heavy endpoints ({status_str}):")
        for r in matching:
            if exact_code is not None:
                filtered = {exact_code: r["by_status"][exact_code]}
            else:
                filtered = {
                    code: cnt for code, cnt in r["by_status"].items()
                    if str(code)[0] == cls_digit
                }
            total = sum(filtered.values())
            by = "  ".join(
                f"{code}={cnt}"
                for code, cnt in sorted(filtered.items(), key=lambda x: -x[1])
            )
            w(f"  {r['endpoint']:<34}  total={total:<6}  {by}")
        w("")
