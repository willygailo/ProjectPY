"""Unit tests for HTTP security headers, banner disclosure, and Set-Cookie flags."""

from __future__ import annotations

from s1shell.profile.header_check import analyze_headers, detect_http3_from_alt_svc


def test_analyze_headers_flags_missing_and_weak_headers_and_banners() -> None:
    headers = [
        ("Server", "nginx/1.18.0"),
        ("X-Powered-By", "PHP/8.1"),
        ("Strict-Transport-Security", "max-age=3600"),
        ("X-Content-Type-Options", "nosniff"),
        ("Set-Cookie", "session=abc; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "prefs=1; Secure"),
    ]
    analysis = analyze_headers(headers, is_https=True)
    by_name = {f.header: f for f in analysis.security_headers}

    assert by_name["Strict-Transport-Security"].status == "weak"
    assert by_name["X-Content-Type-Options"].status == "ok"
    assert by_name["Content-Security-Policy"].status == "missing"
    assert by_name["X-Frame-Options"].status == "missing"
    assert len(analysis.banner_disclosures) == 2
    assert len(analysis.cookies) == 2
    assert analysis.cookies[0].name == "session"
    assert analysis.cookies[0].secure is False
    assert analysis.cookies[0].http_only is True
    assert analysis.cookies[0].same_site == "Lax"


def test_detect_http3_from_alt_svc() -> None:
    assert detect_http3_from_alt_svc('h3=":443"; ma=86400') is True
    assert detect_http3_from_alt_svc('h3-29=":443"; ma=86400') is True
    assert detect_http3_from_alt_svc('h2=":443"; ma=86400') is False
    assert detect_http3_from_alt_svc(None) is False


def test_analyze_headers_flags_weak_csp_referrer_coop_and_multi_banners() -> None:
    headers = [
        ("Content-Security-Policy", "default-src * 'unsafe-inline'"),
        ("Referrer-Policy", "unsafe-url"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-site"),
        ("Via", "1.1 varnish"),
        ("Via", "1.1 cloudfront"),
    ]
    analysis = analyze_headers(headers, is_https=True)
    by_name = {f.header: f for f in analysis.security_headers}

    assert by_name["Content-Security-Policy"].status == "weak"
    assert by_name["Referrer-Policy"].status == "weak"
    assert by_name["Cross-Origin-Opener-Policy"].status == "ok"
    assert by_name["Cross-Origin-Resource-Policy"].status == "ok"
    assert [b.value for b in analysis.banner_disclosures] == ["1.1 varnish", "1.1 cloudfront"]
