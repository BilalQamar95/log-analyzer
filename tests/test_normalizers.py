import pytest
from log_analyzer.normalizers import (
    normalize_timestamp,
    normalize_response_time,
    normalize_status,
    normalize_path,
    status_class,
)


class TestNormalizeTimestamp:
    @pytest.mark.parametrize("value,expected_iso", [
        ("2024-03-15T14:23:01Z",        "2024-03-15T14:23:01+00:00"),
        ("2024-03-15T14:23:01",         "2024-03-15T14:23:01+00:00"),
        ("2024-03-15T14:23:01.000Z",    "2024-03-15T14:23:01+00:00"),
        ("2024-03-15T14:23:01.000",     "2024-03-15T14:23:01+00:00"),
        ("2024/03/15 14:23:01",         "2024-03-15T14:23:01+00:00"),
        ("15-Mar-2024 14:23:01",        "2024-03-15T14:23:01+00:00"),
        ("1710512581",                  "2024-03-15T14:23:01+00:00"),  # epoch seconds str
        (1710512581,                    "2024-03-15T14:23:01+00:00"),  # epoch seconds int
        ("1710512581000",               "2024-03-15T14:23:01+00:00"),  # epoch millis
        ("  2024-03-15T14:23:01Z  ",   "2024-03-15T14:23:01+00:00"),  # leading/trailing whitespace
    ])
    def test_valid(self, value, expected_iso):
        result = normalize_timestamp(value)
        assert result is not None
        assert result.isoformat() == expected_iso
        assert result.tzinfo is not None

    @pytest.mark.parametrize("value", [
        None,
        "",
        "   ",
        "abc",
        "0",          # epoch 0 — treated as missing (epoch floor deviation)
        "-500",       # negative epoch
        "not-a-date",
        "2024-99-99", # invalid calendar date
    ])
    def test_invalid_returns_none(self, value):
        assert normalize_timestamp(value) is None


class TestNormalizeResponseTime:
    @pytest.mark.parametrize("value,expected_ms", [
        ("142ms",     142.0),
        ("0.142s",    142.0),
        ("142",       142.0),
        ("0ms",       0.0),
        ("0",         0.0),
        ("1.5s",      1500.0),
        ("  142ms  ", 142.0),  # whitespace
    ])
    def test_valid(self, value, expected_ms):
        assert normalize_response_time(value) == pytest.approx(expected_ms)

    @pytest.mark.parametrize("value", [
        None,
        "",
        "-",
        "-500ms",  # negative
        "-0.1s",
        "abc",
        "msms",
    ])
    def test_invalid_returns_none(self, value):
        assert normalize_response_time(value) is None


class TestNormalizeStatus:
    @pytest.mark.parametrize("value,expected", [
        ("200", 200),
        ("404", 404),
        ("500", 500),
        ("100", 100),
        ("599", 599),
        (200, 200),   # int input
    ])
    def test_valid(self, value, expected):
        assert normalize_status(value) == expected

    @pytest.mark.parametrize("value", [
        None,
        "",
        "-",
        "0",
        "99",
        "600",
        "999",
        "-1",
        "abc",
        "2OO",  # letter O not zero
    ])
    def test_invalid_returns_none(self, value):
        assert normalize_status(value) is None


class TestNormalizePath:
    @pytest.mark.parametrize("path,expected", [
        ("/api/users/12",                              "/api/users/:id"),
        ("/api/users/0",                               "/api/users/:id"),
        ("/api/users/12/profile",                      "/api/users/:id/profile"),
        ("/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/:uuid"),
        ("/api/trace/abcdef1234567890ab",              "/api/trace/:hex"),
        ("/api/users?page=1",                          "/api/users"),
        ("/api/users?a=1&b=2",                         "/api/users"),
        ("/api/users",                                 "/api/users"),
        ("/",                                          "/"),
        ("",                                           ""),
    ])
    def test_normalization(self, path, expected):
        assert normalize_path(path) == expected


class TestStatusClass:
    @pytest.mark.parametrize("status,expected", [
        (200, "2xx"),
        (201, "2xx"),
        (299, "2xx"),
        (301, "3xx"),
        (399, "3xx"),
        (404, "4xx"),
        (499, "4xx"),
        (500, "5xx"),
        (599, "5xx"),
        (None, "missing"),
        (600, "other"),
        (99,  "other"),
    ])
    def test_classes(self, status, expected):
        assert status_class(status) == expected
