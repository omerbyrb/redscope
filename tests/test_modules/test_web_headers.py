from unittest.mock import patch, MagicMock
import requests

from core.config import load_config
from modules.web.headers import Module as HeadersModule


def _make_response(headers: dict, status_code: int = 200, url: str = "https://example.com"):
    resp = MagicMock(spec=requests.Response)
    resp.headers = headers
    resp.status_code = status_code
    resp.url = url
    resp.history = []
    return resp


def test_all_security_headers_present():
    cfg = load_config()
    mod = HeadersModule(cfg)

    good_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    with patch("modules.web.headers.requests.get", return_value=_make_response(good_headers)):
        result = mod.run("https://example.com")

    missing = [f for f in result.findings if "Missing" in f.title]
    assert len(missing) == 0


def test_missing_csp_flagged():
    cfg = load_config()
    mod = HeadersModule(cfg)

    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    with patch("modules.web.headers.requests.get", return_value=_make_response(headers)):
        result = mod.run("https://example.com")

    titles = [f.title for f in result.findings]
    assert any("Content-Security-Policy" in t for t in titles)


def test_server_header_leaks():
    cfg = load_config()
    mod = HeadersModule(cfg)

    headers = {
        "Server": "Apache/2.4.51 (Debian)",
        "X-Powered-By": "PHP/7.4.3",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    with patch("modules.web.headers.requests.get", return_value=_make_response(headers)):
        result = mod.run("https://example.com")

    titles = [f.title for f in result.findings]
    assert any("Server Version" in t or "Information" in t or "Disclosure" in t for t in titles)


def test_no_crash_on_connection_error():
    cfg = load_config()
    mod = HeadersModule(cfg)

    with patch("modules.web.headers.requests.get", side_effect=requests.exceptions.ConnectionError):
        result = mod.run("https://unreachable.example.com")

    assert len(result.errors) > 0
