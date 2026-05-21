import gzip
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from log_analyzer.cli import main


ADVERSARIAL = Path(__file__).parent / "fixtures" / "adversarial.log"

# One valid STANDARD log line to use across tests
VALID_LINE = "2024-03-15T14:23:01Z 10.0.0.1 GET /api/users 200 42ms\n"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_json_flag_returns_zero_and_valid_json(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        rc = main([str(f), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        for key in ("total_lines", "parsed_lines", "anomaly_count", "parse_success_rate"):
            assert key in data

    def test_default_text_mode_returns_zero(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        rc = main([str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Total lines:" in out

    def test_empty_file_returns_zero(self, tmp_path, capsys):
        f = tmp_path / "empty.log"
        f.write_text("")
        rc = main([str(f), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["total_lines"] == 0

    def test_adversarial_fixture_returns_zero(self, capsys):
        rc = main([str(ADVERSARIAL), "--json"])
        assert rc == 0


# ---------------------------------------------------------------------------
# File access errors → exit 2
# ---------------------------------------------------------------------------

class TestFileErrors:
    def test_file_not_found_returns_two(self, capsys):
        rc = main(["/does/not/exist/ever.log"])
        assert rc == 2
        assert "file not found" in capsys.readouterr().err

    def test_directory_returns_two(self, tmp_path, capsys):
        rc = main([str(tmp_path)])
        assert rc == 2
        assert "directory" in capsys.readouterr().err

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod 000 unreliable on Windows")
    def test_permission_denied_returns_two(self, tmp_path, capsys):
        f = tmp_path / "noperm.log"
        f.write_text(VALID_LINE)
        os.chmod(f, 0)
        try:
            rc = main([str(f)])
            assert rc == 2
            assert "cannot read" in capsys.readouterr().err
        finally:
            os.chmod(f, stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# Gzip support (deviation #9)
# ---------------------------------------------------------------------------

class TestGzip:
    def test_gzip_file_parses_successfully(self, tmp_path, capsys):
        gz = tmp_path / "test.log.gz"
        with gzip.open(gz, "wt", encoding="utf-8") as f:
            f.write(VALID_LINE)
        rc = main([str(gz), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["parsed_lines"] == 1

    def test_corrupt_gzip_returns_two(self, tmp_path, capsys):
        bad = tmp_path / "corrupt.gz"
        bad.write_bytes(b"\x1f\x8b" + b"this is not real gzip data at all, garbage garbage")
        rc = main([str(bad)])
        assert rc == 2
        assert "cannot read" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# UTF-8 BOM handling (deviation #4)
# ---------------------------------------------------------------------------

class TestBOM:
    def test_bom_stripped_line_parses(self, tmp_path, capsys):
        f = tmp_path / "bom.log"
        # Write BOM + valid log line in binary mode
        f.write_bytes(b"\xef\xbb\xbf" + VALID_LINE.encode("utf-8"))
        rc = main([str(f), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["parsed_lines"] == 1


# ---------------------------------------------------------------------------
# BrokenPipeError handling (deviation #6)
# ---------------------------------------------------------------------------

class TestBrokenPipe:
    def test_broken_pipe_returns_zero(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        with patch("log_analyzer.reporter.JsonReporter.render", side_effect=BrokenPipeError):
            rc = main([str(f), "--json"])
        assert rc == 0


# ---------------------------------------------------------------------------
# Invariant via JSON output (deviation #8)
# ---------------------------------------------------------------------------

class TestInvariantViaJson:
    def test_parsed_plus_anomalies_equals_total(self, capsys):
        main([str(ADVERSARIAL), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["parsed_lines"] + data["anomaly_count"] == data["total_lines"]


# ---------------------------------------------------------------------------
# Flag passthrough (args parse without error)
# ---------------------------------------------------------------------------

class TestFlagPassthrough:
    def test_slowest_flag(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        assert main([str(f), "--slowest", "5"]) == 0

    def test_errors_flag(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        assert main([str(f), "--errors"]) == 0

    def test_anomalies_flag(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        assert main([str(f), "--anomalies"]) == 0

    def test_status_flag(self, tmp_path, capsys):
        f = tmp_path / "test.log"
        f.write_text(VALID_LINE)
        assert main([str(f), "--status", "5xx"]) == 0


# ---------------------------------------------------------------------------
# CRLF line endings (Windows-authored logs)
# ---------------------------------------------------------------------------

class TestCRLF:
    def test_crlf_line_parses_correctly(self, tmp_path, capsys):
        f = tmp_path / "crlf.log"
        f.write_bytes(VALID_LINE.rstrip("\n").encode("utf-8") + b"\r\n")
        rc = main([str(f), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["parsed_lines"] == 1
        assert data["anomaly_count"] == 0
