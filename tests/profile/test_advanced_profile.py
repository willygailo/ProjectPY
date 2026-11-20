"""Offline unit tests for advanced DNS, TLS/SPKI, HTTP headers, HTML, well-known, and OPTIONS."""

from __future__ import annotations

from datetime import datetime, timezone

import dns.resolver
import httpx

from s1shell.config import RuntimeConfig
from s1shell.fingerprint.matcher import match_signatures
from s1shell.profile.dns_check import collect_dns_records, count_spf_lookups, parse_dmarc_policy
from s1shell.profile.header_check import analyze_headers
from s1shell.profile.html_check import analyze_html_body
from s1shell.profile.tls_check import analyze_cipher_suite
from s1shell.profile.well_known import (
    inspect_http_methods,
    inspect_well_known,
    parse_allowed_methods,
    parse_robots_txt_full,
    parse_security_txt_full,
)
from s1shell.scope import parse_target


def test_dns_security_hygiene_apex_fallback_and_dangling_cname() -> None:
    class MockDNS:
        def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
            _ = lifetime
            table: dict[tuple[str, str], list[str]] = {
                ("app.example.com", "A"): ["93.184.216.34"],
                ("app.example.com", "CNAME"): ["stale-site.github.io"],
                ("app.example.com", "MX"): ["10 mail.example.com"],
                ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
                ("example.com", "NS"): ["ns1.example.com"],
                (
                    "example.com",
                    "TXT",
                ): [
                    '"v=spf1 include:a.ex include:b.ex include:c.ex include:d.ex '
                    "include:e.ex include:f.ex include:g.ex include:h.ex include:i.ex "
                    'include:j.ex include:k.ex ?all"'
                ],
                ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'],
                ("example.com", "DS"): ["12345 13 2 DEADBEEF"],
            }
            if qname == "stale-site.github.io":
                raise dns.resolver.NXDOMAIN()
            if (qname, rdtype) in table:
                return table[(qname, rdtype)]
            raise dns.resolver.NoAnswer()

    res = collect_dns_records(
        "app.example.com",
        is_ip=False,
        resolver=MockDNS(),
        include_security=True,
    )
    assert res.security_checked is True
    assert res.apex_domain == "example.com"
    assert res.caa == ['0 issue "letsencrypt.org"']
    assert res.dmarc_policy == "none"
    assert res.spf_lookup_count == 11
    assert res.dnssec_present is True
    assert res.dangling_cnames == ["stale-site.github.io"]
    assert res.mx == ["10 mail.example.com"]
    assert res.ns == ["ns1.example.com"]
    assert count_spf_lookups("v=spf1 include:_spf.google.com mx a -all") == 3
    assert parse_dmarc_policy("v=DMARC1; p=reject; pct=100") == "reject"


def test_cipher_suite_and_advanced_header_cache_debug_analysis() -> None:
    weak = analyze_cipher_suite("AES128-CBC-SHA", "TLSv1.2")
    assert any("CBC" in w for w in weak)
    assert any("SHA-1" in w for w in weak)
    assert any("Forward Secrecy" in w for w in weak)
    assert analyze_cipher_suite("TLS_AES_256_GCM_SHA384", "TLSv1.3") == []

    headers = [
        ("Content-Security-Policy", "script-src 'self' https://cdnjs.cloudflare.com"),
        ("Cache-Control", "public, max-age=3600"),
        ("X-Debug-Token", "a1b2c3d4"),
        ("Set-Cookie", "session_id=xyz; Domain=.example.com; Max-Age=9999999"),
        ("Set-Cookie", "__Host-auth=1; Path=/app; Domain=example.com"),
    ]
    analysis = analyze_headers(headers, is_https=True)
    csp_h = next(h for h in analysis.security_headers if h.header == "Content-Security-Policy")
    assert csp_h.status == "weak"
    assert "cdnjs.cloudflare.com" in csp_h.note
    assert analysis.cache_issues
    assert [d.header for d in analysis.debug_headers] == ["X-Debug-Token"]
    assert analysis.cookies[0].is_session_like is True
    assert analysis.cookies[0].domain == ".example.com"
    assert len(analysis.cookies[1].prefix_issues) == 3


def test_passive_html_analysis_and_client_library_cpe_fingerprinting() -> None:
    html_bytes = b"""<!doctype html>
    <html>
      <head>
        <title>Portal Login</title>
        <meta name="generator" content="WordPress 6.5.2">
        <script src="https://cdn.example.net/jquery-2.1.4.min.js"></script>
        <script src="http://insecure.cdn.org/lodash/4.17.15/lodash.min.js"></script>
        <script>console.log("inline");</script>
      </head>
      <body>
        <form action="/login" method="GET">
          <input type="password" name="pw">
        </form>
        <a href="https://partner.example.org/docs" target="_blank">Partner</a>
      </body>
    </html>"""
    parsed = analyze_html_body(
        html_bytes,
        headers=[("Content-Type", "text/html; charset=utf-8")],
        page_url="https://app.example.com/",
    )
    assert parsed.analyzed is True
    assert parsed.title == "Portal Login"
    assert parsed.inline_script_count == 1
    assert parsed.unsafe_blank_links == 1
    assert "jquery/2.1.4" in parsed.detected_libraries
    assert "lodash/4.17.15" in parsed.detected_libraries
    assert "cdn.example.net" in parsed.third_party_origins
    assert any("HTTP GET" in f for f in parsed.insecure_forms)
    assert len(parsed.mixed_content_urls) == 1
    assert len(parsed.external_scripts_without_sri) == 2

    # Zero-extra-packet passive client library CPE matching
    matches = match_signatures([], html_analysis=parsed)
    by_prod = {m.product: m for m in matches}
    assert "jQuery" in by_prod
    assert by_prod["jQuery"].version == "2.1.4"
    assert by_prod["jQuery"].cpe == "cpe:2.3:a:jquery:jquery:2.1.4:*:*:*:*:*:*:*"
    assert "Lodash" in by_prod
    assert by_prod["Lodash"].cpe == "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:*:*:*"
    assert "WordPress" in by_prod
    assert by_prod["WordPress"].version == "6.5.2"


def test_well_known_and_options_method_inspection(tmp_config: RuntimeConfig) -> None:
    sec_text = (
        "Contact: mailto:sec@example.com\n"
        "Canonical: https://example.com/.well-known/security.txt\n"
        "Encryption: https://example.com/pgp.txt\n"
        "Policy: https://example.com/policy\n"
        "Expires: 2020-01-01T00:00:00Z\n"
    )
    parsed_sec = parse_security_txt_full(sec_text, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert parsed_sec.contacts == ["mailto:sec@example.com"]
    assert parsed_sec.expired is True
    assert parsed_sec.canonical == "https://example.com/.well-known/security.txt"

    rob_text = (
        "User-agent: *\n"
        "Disallow: /admin-panel\n"
        "Disallow: /actuator/health\n"
        "Sitemap: https://example.com/sitemap.xml\n"
    )
    cnt, hints, sitemaps = parse_robots_txt_full(rob_text)
    assert cnt == 2
    assert "/admin-panel" in hints
    assert "/actuator/health" in hints
    assert sitemaps == ["https://example.com/sitemap.xml"]

    methods, risky = parse_allowed_methods([("Allow", "GET, HEAD, OPTIONS, TRACE, DELETE")])
    assert methods == ["GET", "HEAD", "OPTIONS", "TRACE", "DELETE"]
    assert risky == ["TRACE", "DELETE"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS, TRACE, PUT"})
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(200, text=sec_text)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=rob_text)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    parsed_tgt = parse_target("https://example.com/")
    wk = inspect_well_known(
        tmp_config,
        parsed=parsed_tgt,
        pinned_ip="93.184.216.34",
        http_transport=transport,
    )
    assert wk.security_txt_present is True
    assert wk.security_txt_expired is True
    assert wk.robots_txt_present is True
    assert wk.robots_sitemaps == ["https://example.com/sitemap.xml"]

    allowed, flagged = inspect_http_methods(
        tmp_config,
        parsed=parsed_tgt,
        pinned_ip="93.184.216.34",
        http_transport=transport,
    )
    assert "TRACE" in flagged
    assert "PUT" in flagged
    assert "GET" in allowed
