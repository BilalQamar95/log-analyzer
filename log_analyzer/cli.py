import argparse
import gzip
import sys
from typing import List, Optional

from log_analyzer.analyzer import Analyzer
from log_analyzer.parser import Parser
from log_analyzer.reporter import JsonReporter, TextReporter


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loganalyze", description="Analyze server log files.")
    p.add_argument("path", help="Path to log file (plain or gzip-compressed)")
    p.add_argument("--slowest", type=int, default=None, metavar="N",
                   help="Show top N slowest endpoints by p95 (default 10)")
    p.add_argument("--errors", action="store_true",
                   help="Show only error-heavy endpoints section")
    p.add_argument("--anomalies", action="store_true",
                   help="Show only anomaly samples section")
    p.add_argument("--status", default=None, metavar="CODE",
                   help="Filter to a specific status code or class (e.g. 500 or 5xx)")
    p.add_argument("--json", action="store_true",
                   help="Emit machine-readable JSON output")
    return p


def _open_log(path: str):
    with open(path, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return open(path, "r", encoding="utf-8-sig", errors="replace")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    try:
        log_file = _open_log(args.path)
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: path is a directory: {args.path}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"error: cannot read: {args.path}", file=sys.stderr)
        return 2

    parser = Parser()
    analyzer = Analyzer()

    try:
        with log_file as f:
            for line_no, raw_line in enumerate(f, start=1):
                analyzer.consume(parser.parse(raw_line.rstrip("\r\n"), line_no))
    except (OSError, EOFError) as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2

    snapshot = analyzer.snapshot()
    reporter = JsonReporter() if args.json else TextReporter()

    try:
        reporter.render(snapshot, args, sys.stdout)
    except BrokenPipeError:
        return 0

    return 0
