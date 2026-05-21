import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

from log_analyzer.cli import main


FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = FIXTURES / "clean.log"
MESSY = FIXTURES / "messy.log"
ADVERSARIAL = FIXTURES / "adversarial.log"

ALL_FIXTURES = [
    pytest.param(str(CLEAN), id="clean"),
    pytest.param(str(MESSY), id="messy"),
    pytest.param(str(ADVERSARIAL), id="adversarial"),
]

ALL_FLAGS = [
    pytest.param([], id="no-flag"),
    pytest.param(["--json"], id="json"),
    pytest.param(["--errors"], id="errors"),
    pytest.param(["--anomalies"], id="anomalies"),
    pytest.param(["--status", "5xx"], id="status-5xx"),
    pytest.param(["--slowest", "5"], id="slowest-5"),
    pytest.param(["--slowest", "0"], id="slowest-0"),
]


# ---------------------------------------------------------------------------
# Per-fixture parse-quality assertions
# ---------------------------------------------------------------------------

class TestCleanFixture:
    def test_full_parse(self, capsys):
        rc = main([str(CLEAN), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["total_lines"] == data["parsed_lines"]
        assert data["anomaly_count"] == 0
        assert data["parse_success_rate"] == 1.0

    def test_format_counts_present(self, capsys):
        main([str(CLEAN), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert sum(data["format_counts"].values()) == data["total_lines"]


class TestMessyFixture:
    def test_has_anomalies(self, capsys):
        rc = main([str(MESSY), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["anomaly_count"] > 0
        assert data["parse_success_rate"] > 0.85

    def test_multiple_formats_present(self, capsys):
        main([str(MESSY), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert len(data["format_counts"]) >= 2


class TestAdversarialFixture:
    def test_exit_zero_no_crash(self, capsys):
        rc = main([str(ADVERSARIAL), "--json"])
        assert rc == 0

    def test_multiple_anomaly_kinds(self, capsys):
        main([str(ADVERSARIAL), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert len(data["anomalies"]["counts"]) >= 2


# ---------------------------------------------------------------------------
# Invariant holds across all fixtures
# ---------------------------------------------------------------------------

class TestInvariantAllFixtures:
    @pytest.mark.parametrize("fixture_path", ALL_FIXTURES)
    def test_invariant(self, fixture_path, capsys):
        main([fixture_path, "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["parsed_lines"] + data["anomaly_count"] == data["total_lines"]


# ---------------------------------------------------------------------------
# Flag matrix against messy fixture
# ---------------------------------------------------------------------------

class TestFlagMatrix:
    def test_errors_flag(self, capsys):
        rc = main([str(MESSY), "--errors"])
        assert rc == 0
        assert "Error-heavy endpoints" in capsys.readouterr().out

    def test_anomalies_flag(self, capsys):
        rc = main([str(MESSY), "--anomalies"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Anomalies" in out

    def test_status_class_filter(self, capsys):
        rc = main([str(MESSY), "--status", "5xx"])
        assert rc == 0
        assert "Status filter: 5xx" in capsys.readouterr().out

    def test_status_exact_filter(self, capsys):
        rc = main([str(MESSY), "--status", "500"])
        assert rc == 0
        assert "Status filter: 500" in capsys.readouterr().out

    def test_slowest_5(self, capsys):
        rc = main([str(MESSY), "--slowest", "5"])
        assert rc == 0
        assert "top 5" in capsys.readouterr().out

    def test_slowest_0_does_not_default_to_10(self, capsys):
        rc = main([str(MESSY), "--slowest", "0"])
        assert rc == 0
        assert "top 10" not in capsys.readouterr().out

    def test_json_flag_all_keys(self, capsys):
        rc = main([str(MESSY), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        for key in ("total_lines", "parsed_lines", "anomaly_count", "parse_success_rate",
                    "format_counts", "status_class_counts", "top_endpoints", "top_ips",
                    "date_range", "global_latency", "anomalies", "field_warnings"):
            assert key in data


# ---------------------------------------------------------------------------
# Edge-case fixtures (inline, no committed file)
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_file_exit_zero(self, tmp_path, capsys):
        f = tmp_path / "empty.log"
        f.write_text("")
        rc = main([str(f), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["total_lines"] == 0

    def test_non_log_content_all_anomalies(self, tmp_path, capsys):
        f = tmp_path / "hosts.log"
        f.write_text("127.0.0.1  localhost\n::1        localhost\n255.255.255.255  broadcasthost\n")
        rc = main([str(f), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["parse_success_rate"] == 0.0

    @pytest.mark.skipif(not Path("/dev/null").exists(), reason="no /dev/null")
    def test_dev_null_exit_zero(self, capsys):
        rc = main(["/dev/null", "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["total_lines"] == 0


# ---------------------------------------------------------------------------
# Process-level broken-pipe test
# ---------------------------------------------------------------------------

class TestBrokenPipe:
    def test_pipe_to_head_no_traceback(self):
        loganalyze = Path(__file__).parent.parent / "loganalyze.py"
        proc = subprocess.run(
            [sys.executable, str(loganalyze), str(MESSY)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0
        assert b"Traceback" not in proc.stderr


# ---------------------------------------------------------------------------
# Acceptance smoke — all fixtures × all flags
# ---------------------------------------------------------------------------

class TestAcceptanceSmoke:
    @pytest.mark.parametrize("fixture_path", ALL_FIXTURES)
    @pytest.mark.parametrize("flags", ALL_FLAGS)
    def test_no_crash(self, fixture_path, flags, capsys):
        rc = main([fixture_path] + flags)
        assert rc == 0
