"""Unit tests for passive signature matching."""

from __future__ import annotations

from s1shell.fingerprint.matcher import match_signatures


def test_match_signatures_identifies_server_cdn_and_framework() -> None:
    headers = [
        ("Server", "nginx/1.18.0"),
        ("X-Powered-By", "Express"),
        ("X-Amz-Cf-Id", "abc123"),
        ("Set-Cookie", "PHPSESSID=xyz; HttpOnly"),
    ]
    matches = match_signatures(headers, tls_issuer=None)
    products = {m.product for m in matches}
    assert "nginx" in products
    assert "Express" in products
    assert "Amazon CloudFront" in products
    assert "PHP" in products


def test_match_signatures_uses_tls_issuer_and_cookies() -> None:
    headers = [
        ("CF-RAY", "1234-LAX"),
        ("Set-Cookie", "__cf_bm=tok; Secure"),
    ]
    matches = match_signatures(headers, tls_issuer="CN=Cloudflare Inc ECC CA-3")
    assert len(matches) == 1
    assert matches[0].product == "Cloudflare CDN/WAF"
    assert matches[0].confidence == "high"
    assert len(matches[0].evidence) == 3


def test_match_signatures_extracts_versions_and_extended_signatures() -> None:
    headers = [
        ("Server", "nginx/1.18.0"),
        ("X-Powered-By", "Next.js 14.1.0"),
        ("X-Vercel-Id", "sfo1::abc"),
        ("Set-Cookie", "BIGipServerPool=123; Secure"),
        ("Set-Cookie", "wordpress_logged_in_abc=xyz; HttpOnly"),
    ]
    matches = match_signatures(headers, tls_issuer=None)
    by_prod = {m.product: m for m in matches}
    assert by_prod["nginx"].version == "1.18.0"
    assert by_prod["Next.js"].version == "14.1.0"
    assert "Vercel Edge" in by_prod
    assert "F5 BIG-IP" in by_prod
    assert "WordPress" in by_prod
