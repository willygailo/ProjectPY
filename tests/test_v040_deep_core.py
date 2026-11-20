"""Offline tests for S1shell v0.4.0 Deep Core features."""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.assess.scorer import evaluate_posture_with_suppressions
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import (
    DependencyAuditService,
    OSVClient,
    _extract_osv_severity,
    build_upgrade_commands,
    discover_dependency_files,
    parse_dependency_file,
)
from s1shell.cve.cvss import calculate_cvss3_base_score
from s1shell.cve.models import DependencyVuln
from s1shell.fingerprint.eol import check_product_eol
from s1shell.fingerprint.matcher import match_signatures
from s1shell.fingerprint.models import FingerprintMatch, FingerprintResult
from s1shell.intel.clients import (
    CrtShClient,
    RDAPClient,
    parse_crtsh_payload,
    parse_rdap_payload,
)
from s1shell.intel.models import IntelLookupResult, RDAPLookupResult, URLScanSummary
from s1shell.intel.service import IntelService
from s1shell.mcp_server import S1ShellMCPServer
from s1shell.profile.dns_check import _candidate_apex, analyze_spf_recursive, collect_dns_records
from s1shell.profile.header_check import analyze_headers
from s1shell.profile.html_check import analyze_html_body, inspect_passive_jwt
from s1shell.profile.models import (
    DNSRecords,
    ProfileResult,
    ProtocolInfo,
    TLSResult,
)
from s1shell.profile.tls_check import analyze_cert_chain, check_caa_issuer_alignment
from s1shell.profile.well_known import (
    inspect_well_known,
    parse_jwks_payload,
    parse_oidc_configuration,
)
from s1shell.report.sarif import render_dependency_sarif
from s1shell.scope import parse_target


def _make_cert_der(
    cn: str,
    *,
    issuer_cn: str | None = None,
    days_valid: int = 90,
    key_size: int = 2048,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = datetime.now(timezone.utc)
    if days_valid >= 0:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)
    else:
        not_before = now + timedelta(days=days_valid - 30)
        not_after = now + timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(iss)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hash_alg or hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_crtsh_ct_and_rdap_service_cache_cli_and_mcp(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
    tmp_path: Path,
) -> None:
    ct_calls = 0
    rdap_calls = 0

    def ct_handler(req: httpx.Request) -> httpx.Response:
        nonlocal ct_calls
        ct_calls += 1
        assert req.url.params.get("output") == "json"
        return httpx.Response(
            200,
            json=[
                {
                    "id": 1001,
                    "common_name": "app.example.com",
                    "name_value": "app.example.com\n*.dev.example.com\napi.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                },
                {
                    "id": 1002,
                    "common_name": "legacy.example.com",
                    "name_value": "legacy.example.com",
                    "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert",
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2021-01-01T00:00:00Z",
                },
            ],
        )

    def rdap_handler(_req: httpx.Request) -> httpx.Response:
        nonlocal rdap_calls
        rdap_calls += 1
        return httpx.Response(
            200,
            json={
                "ldhName": "example.com",
                "handle": "DOM-123",
                "status": ["active"],
                "secureDNS": {"delegationSigned": True},
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-12-01T00:00:00Z"},
                ],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]],
                        "entities": [
                            {
                                "roles": ["abuse"],
                                "vcardArray": [
                                    "vcard",
                                    [["email", {}, "text", "abuse@registrar.example"]],
                                ],
                            }
                        ],
                    }
                ],
            },
        )

    svc = IntelService(
        tmp_config,
        crtsh_client=CrtShClient(tmp_config, transport=httpx.MockTransport(ct_handler)),
        rdap_client=RDAPClient(tmp_config, transport=httpx.MockTransport(rdap_handler)),
        audit_logger=audit_logger,
    )
    cand_file = tmp_path / "candidates.txt"
    ct_res = svc.ct_lookup("example.com", export_candidates=cand_file)
    assert ct_res.total_certificates == 2
    assert ct_res.active_certificates == 1
    assert ct_res.expired_certificates == 1
    assert "api.example.com" in ct_res.unique_subdomains
    assert "*.dev.example.com" in ct_res.wildcard_sans
    assert cand_file.is_file()
    assert "api.example.com" in cand_file.read_text(encoding="utf-8")

    # Offline cache hit -> zero additional network requests
    ct_cached = svc.ct_lookup("example.com", offline=True)
    assert ct_cached.cached is True
    assert ct_calls == 1

    # RDAP lookup + cache hit
    rdap_res = svc.rdap_lookup("example.com")
    assert rdap_res.registrar == "Example Registrar Inc"
    assert rdap_res.abuse_contact == "abuse@registrar.example"
    assert rdap_res.transfer_locked is False
    assert rdap_res.dnssec_signed is True
    assert rdap_res.nameservers == ["ns1.example.com"]
    rdap_cached = svc.rdap_lookup("example.com", offline=True)
    assert rdap_cached.cached is True
    assert rdap_calls == 1

    # CLI dispatch for `intel ct` and `intel rdap`
    parser = build_parser()
    out_ct = io.StringIO()
    rc = dispatch(
        parser.parse_args(["--format", "json", "intel", "ct", "example.com", "--offline"]),
        stdout=out_ct,
        stderr=io.StringIO(),
        intel_service=svc,
    )
    assert rc == 0
    assert json.loads(out_ct.getvalue())["artifact_type"] == "ct_report"

    out_rdap = io.StringIO()
    rc2 = dispatch(
        parser.parse_args(["--format", "json", "intel", "rdap", "example.com", "--offline"]),
        stdout=out_rdap,
        stderr=io.StringIO(),
        intel_service=svc,
    )
    assert rc2 == 0
    assert json.loads(out_rdap.getvalue())["artifact_type"] == "rdap_report"

    # MCP tools `s1shell_intel_ct` and `s1shell_intel_rdap`
    mcp = S1ShellMCPServer(tmp_config, intel_service=svc)
    list_resp = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert list_resp is not None
    tool_names = [t["name"] for t in list_resp["result"]["tools"]]
    assert "s1shell_intel_ct" in tool_names
    assert "s1shell_intel_rdap" in tool_names

    ct_mcp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "s1shell_intel_ct",
                "arguments": {"domain": "example.com", "offline": True},
            },
        }
    )
    assert ct_mcp is not None and ct_mcp["result"]["isError"] is False
    assert parse_crtsh_payload([], domain="example.com").total_certificates == 0

    ip_rdap = parse_rdap_payload(
        {
            "handle": "NET-93-184-216-0-1",
            "country": "US",
            "startAddress": "93.184.216.0",
            "endAddress": "93.184.216.255",
            "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
        },
        indicator="93.184.216.34",
        indicator_type="ip",
    )
    assert ip_rdap.cidr == "93.184.216.0/24"


def test_tls_chain_caa_alignment_and_recursive_spf_bimi_tlsa_psl() -> None:
    leaf_only = _make_cert_der("app.example.com", issuer_cn="Intermediate CA", days_valid=90)
    entries_1, issues_1 = analyze_cert_chain([leaf_only])
    assert len(entries_1) == 1
    assert any("without intermediate CA chain" in msg for msg in issues_1)

    inter_expired = _make_cert_der(
        "Intermediate CA",
        issuer_cn="Root CA",
        days_valid=-5,
    )
    wrong_order = _make_cert_der("Unrelated CA", issuer_cn="Other Root", days_valid=90)
    entries_2, issues_2 = analyze_cert_chain([leaf_only, inter_expired, wrong_order])
    assert len(entries_2) == 3
    assert any("expired" in msg for msg in issues_2)
    assert any("order mismatch" in msg for msg in issues_2)

    assert (
        check_caa_issuer_alignment(['0 issue "letsencrypt.org"'], "O=Let's Encrypt, CN=R10") == []
    )
    mismatch = check_caa_issuer_alignment(['0 issue "digicert.com"'], "O=Let's Encrypt, CN=R10")
    assert len(mismatch) == 1
    assert "does not match DNS CAA" in mismatch[0]

    # Expanded multi-part PSL (e.g. Philippines gov.ph)
    assert _candidate_apex("portal.agency.gov.ph") == "agency.gov.ph"
    assert _candidate_apex("shop.brand.co.id") == "brand.co.id"

    # Recursive SPF (>10 lookups across includes, +all, void lookup, BIMI, TLSA)
    class RecursiveSPFResolver:
        def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
            _ = lifetime
            if qname == "broken.example" and rdtype == "TXT":
                raise dns.resolver.NXDOMAIN()
            table: dict[tuple[str, str], list[str]] = {
                ("example.com", "A"): ["93.184.216.34"],
                (
                    "example.com",
                    "TXT",
                ): ['"v=spf1 include:spfa.example include:broken.example ip4:10.0.0.0/8 +all"'],
                (
                    "spfa.example",
                    "TXT",
                ): [
                    '"v=spf1 include:spfb.example a mx include:c1.ex include:c2.ex '
                    'include:c3.ex include:c4.ex include:c5.ex include:c6.ex -all"'
                ],
                ("spfb.example", "TXT"): ['"v=spf1 a mx include:spfa.example -all"'],
                ("default._bimi.example.com", "TXT"): ['"v=BIMI1; l=https://example.com/logo.svg"'],
                ("_443._tcp.example.com", "TLSA"): ["3 1 1 AABBCCDD"],
            }
            if (qname, rdtype) in table:
                return table[(qname, rdtype)]
            raise dns.resolver.NoAnswer()

    rec_count, voids, issues = analyze_spf_recursive(
        RecursiveSPFResolver(),
        "example.com",
        "v=spf1 include:spfa.example include:broken.example ip4:10.0.0.0/8 +all",
    )
    assert rec_count > 10
    assert voids >= 1
    assert any("+all" in i for i in issues)
    assert any("IPv4 range" in i for i in issues)
    assert any("Recursive SPF requires" in i for i in issues)
    assert any("loop detected" in i for i in issues)

    dns_res = collect_dns_records(
        "example.com", is_ip=False, resolver=RecursiveSPFResolver(), include_security=True
    )
    assert dns_res.bimi is not None and dns_res.bimi.startswith("v=BIMI1")
    assert dns_res.tlsa == ["3 1 1 AABBCCDD"]
    assert dns_res.spf_recursive_lookups is not None and dns_res.spf_recursive_lookups > 10


def test_oidc_jwks_passive_leaks_jwt_csp_v2_eol_and_scorer(tmp_config: RuntimeConfig) -> None:
    issuer, oidc_issues = parse_oidc_configuration(
        {
            "issuer": "http://idp.example.com",
            "authorization_endpoint": "http://idp.example.com/auth",
            "response_types_supported": ["code", "id_token token"],
            "id_token_signing_alg_values_supported": ["RS256", "none"],
            "code_challenge_methods_supported": ["plain"],
        }
    )
    assert issuer == "http://idp.example.com"
    assert len(oidc_issues) >= 4

    weak_n = base64.urlsafe_b64encode(b"\x01" + b"\x00" * 127).decode("ascii").rstrip("=")
    k_count, jwks_issues = parse_jwks_payload(
        {"keys": [{"kty": "RSA", "kid": "k1", "alg": "none", "n": weak_n, "d": "LEAKED_PRIV"}]}
    )
    assert k_count == 1
    assert any("private key material" in i for i in jwks_issues)
    assert any("alg: none" in i for i in jwks_issues)
    assert any("1024 bits" in i or "< 2048" in i for i in jwks_issues)

    def wk_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={"issuer": "http://idp.example.com", "response_types_supported": ["token"]},
            )
        if req.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "k1", "d": "x"}]})
        if req.url.path == "/.well-known/assetlinks.json":
            return httpx.Response(200, json=[{"relation": ["delegate_permission"]}])
        return httpx.Response(404)

    wk = inspect_well_known(
        tmp_config,
        parsed=parse_target("https://example.com/"),
        pinned_ip="93.184.216.34",
        http_transport=httpx.MockTransport(wk_handler),
    )
    assert wk.oidc_present is True and wk.oidc_issues
    assert wk.jwks_present is True and wk.jwks_issues
    assert "/.well-known/assetlinks.json" in wk.mobile_trust_files

    # Zero-extra-packet passive secret leak, JWT, source map, stack trace
    jwt_hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    jwt_pay = base64.urlsafe_b64encode(b'{"sub":"alice","api_key":"x"}').decode().rstrip("=")
    fake_jwt = f"{jwt_hdr}.{jwt_pay}."
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    html_doc = f"""<!doctype html><html><body>
      <script>
        const k = "{raw_aws}";
        const t = "{fake_jwt}";
        //# sourceMappingURL=bundle.min.js.map
      </script>
      <pre>Traceback (most recent call last):\n  File "app.py", line 1</pre>
    </body></html>""".encode()
    html_res = analyze_html_body(
        html_doc,
        headers=[("Content-Type", "text/html")],
        page_url="https://example.com/",
    )
    assert len(html_res.leaked_secrets) == 1
    assert raw_aws not in html_res.leaked_secrets[0]["redacted_preview"]
    assert html_res.leaked_secrets[0]["redacted_preview"].startswith("AKIA****")
    assert len(html_res.passive_jwts) == 1
    assert any("alg:none" in i for i in html_res.passive_jwts[0]["issues"])
    assert html_res.source_maps == ["bundle.min.js.map"]
    assert "python_traceback" in html_res.stack_traces
    assert inspect_passive_jwt(fake_jwt, location="test") is not None

    # CSP v2 checks blob: & wildcard https:
    hdrs = analyze_headers(
        [("Content-Security-Policy", "script-src 'self' blob: https:")], is_https=True
    )
    csp_h = next(h for h in hdrs.security_headers if h.header == "Content-Security-Policy")
    assert csp_h.status == "weak"
    assert "blob:" in csp_h.note and "https:" in csp_h.note

    # Offline EOL check + scorer integration across all v0.4.0 findings
    eol = check_product_eol("nginx", "1.18.0")
    assert eol is not None and eol.is_eol is True
    assert check_product_eol("nginx", "1.28.0") is None

    matches = match_signatures([("Server", "nginx/1.18.0")])
    assert any(m.product == "nginx" and m.eol is True for m in matches)

    prof = ProfileResult(
        target="https://example.com",
        url="https://example.com/",
        pinned_ip="93.184.216.34",
        scope_id="s1",
        auth_ref="SOW-1",
        authorized_via="flag",
        dns=DNSRecords(
            a=["93.184.216.34"],
            caa=['0 issue "digicert.com"'],
            spf="v=spf1 +all",
            spf_issues=["SPF uses `+all`", "Recursive SPF requires 12 DNS lookups"],
            security_checked=True,
        ),
        protocol=ProtocolInfo(status_code=200, http_version="HTTP/2"),
        tls=TLSResult(
            applicable=True,
            negotiated_version="TLSv1.3",
            verified=True,
            issuer="O=Let's Encrypt, CN=R10",
            chain_issues=["Server sent only leaf certificate without intermediate CA chain."],
        ),
        headers=hdrs,
        html=html_res,
        well_known=wk,
    )
    fp = FingerprintResult(
        target=prof.target,
        url=prof.url,
        mode="from_profile",
        scope_id="s1",
        auth_ref="SOW-1",
        matches=[
            FingerprintMatch(
                vendor="F5 / NGINX",
                product="nginx",
                category="web_server",
                confidence="high",
                version="1.18.0",
                eol=True,
                eol_recommended="Upgrade to NGINX 1.26.x+",
            )
        ],
    )
    intel = IntelLookupResult(
        indicator="example.com",
        indicator_type="domain",
        resolved_ip="93.184.216.34",
        urlscan=URLScanSummary(
            query="domain:example.com", total_results=5, observed_ips=["198.51.100.7"]
        ),
        rdap=RDAPLookupResult(
            indicator="example.com",
            indicator_type="domain",
            expires_at="2026-11-25T00:00:00Z",
            days_until_expiry=5,
            transfer_locked=False,
            statuses=["active"],
        ),
    )
    _, findings, _ = evaluate_posture_with_suppressions(prof, fp, intel=intel)
    fmap = {f.id: f for f in findings}
    for expected_id in (
        "TLS-CHAIN",
        "TLS-CAA-MISMATCH",
        "DNS-SPF-PERMISSIVE",
        "DNS-SPF-RECURSIVE",
        "OIDC-001",
        "JWKS-PRIV",
        "LEAK-SECRET",
        "LEAK-JWT",
        "LEAK-SOURCEMAP",
        "LEAK-TRACE",
        "EOL-001",
        "INTEL-RDAP-EXPIRING",
        "INTEL-RDAP-UNLOCKED",
        "INTEL-ORIGIN-DRIFT",
    ):
        assert expected_id in fmap, f"Missing finding {expected_id}"
    assert fmap["JWKS-PRIV"].severity == "CRITICAL"
    assert raw_aws not in fmap["LEAK-SECRET"].evidence


def test_cvss31_calculator_lockfiles_spdx_recursive_audit_and_sarif(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
    tmp_path: Path,
) -> None:
    # Exact FIRST CVSS v3.1 test vectors
    assert calculate_cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (
        9.8,
        "CRITICAL",
    )
    assert calculate_cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == (
        6.1,
        "MEDIUM",
    )
    assert calculate_cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == (
        0.0,
        "INFO",
    )

    # _extract_osv_severity parses CVSS v3.1 vector strings instead of falling back to MEDIUM
    sev, score = _extract_osv_severity(
        {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    )
    assert (sev, score) == ("CRITICAL", 9.8)

    # New lockfile & SPDX 2.3 parsers
    repo = tmp_path / "repo"
    (repo / "backend").mkdir(parents=True)
    (repo / "frontend").mkdir(parents=True)
    (repo / "node_modules" / "ignored").mkdir(parents=True)

    (repo / "backend" / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.25.0"\n', encoding="utf-8"
    )
    (repo / "backend" / "poetry.lock").write_text(
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n', encoding="utf-8"
    )
    (repo / "backend" / "Pipfile.lock").write_text(
        json.dumps({"_meta": {}, "default": {"flask": {"version": "==2.0.1"}}}), encoding="utf-8"
    )
    (repo / "frontend" / "yarn.lock").write_text(
        '"lodash@^4.17.15":\n  version "4.17.15"\n', encoding="utf-8"
    )
    (repo / "frontend" / "pnpm-lock.yaml").write_text(
        "packages:\n  /axios@0.21.1:\n    resolution: {}\n", encoding="utf-8"
    )
    (repo / "composer.lock").write_text(
        json.dumps(
            {"content-hash": "abc", "packages": [{"name": "monolog/monolog", "version": "v2.3.0"}]}
        ),
        encoding="utf-8",
    )
    (repo / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (6.1.0)\n", encoding="utf-8")
    (repo / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>",
        encoding="utf-8",
    )
    (repo / "app.spdx.json").write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [
                    {
                        "name": "django",
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/django@3.2.1"}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (repo / "node_modules" / "ignored" / "package-lock.json").write_text("{}", encoding="utf-8")

    assert parse_dependency_file(repo / "backend" / "uv.lock")[0] == "uv.lock"
    assert parse_dependency_file(repo / "backend" / "poetry.lock")[0] == "poetry.lock"
    assert parse_dependency_file(repo / "backend" / "Pipfile.lock")[0] == "Pipfile.lock"
    assert parse_dependency_file(repo / "frontend" / "yarn.lock")[0] == "yarn.lock"
    assert parse_dependency_file(repo / "frontend" / "pnpm-lock.yaml")[0] == "pnpm-lock.yaml"
    assert parse_dependency_file(repo / "composer.lock")[0] == "composer.lock"
    assert parse_dependency_file(repo / "Gemfile.lock")[0] == "Gemfile.lock"
    assert parse_dependency_file(repo / "pom.xml")[0] == "pom.xml"
    assert parse_dependency_file(repo / "app.spdx.json")[0] == "spdx"

    discovered = discover_dependency_files(repo, recursive=True)
    assert len(discovered) == 9
    assert all("node_modules" not in str(p) for p in discovered)

    # Recursive audit + CVSS v3.1 vector scoring + upgrade commands + per-file SARIF URIs
    def osv_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        results = []
        for q in body["queries"]:
            pkg = q["package"]["name"]
            if pkg == "requests":
                results.append(
                    {
                        "vulns": [
                            {
                                "id": "GHSA-9wx4-h78v-vm56",
                                "aliases": ["CVE-2024-35195"],
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                ],
                                "affected": [
                                    {
                                        "package": {"name": "requests"},
                                        "ranges": [{"events": [{"fixed": "2.32.0"}]}],
                                    }
                                ],
                            }
                        ]
                    }
                )
            elif pkg == "lodash":
                results.append(
                    {
                        "vulns": [
                            {
                                "id": "GHSA-unpatched-test",
                                "summary": "Unpatched test advisory",
                            }
                        ]
                    }
                )
            else:
                results.append({})
        return httpx.Response(200, json={"results": results})

    dep_svc = DependencyAuditService(
        tmp_config,
        osv_client=OSVClient(tmp_config, transport=httpx.MockTransport(osv_handler)),
        audit_logger=audit_logger,
    )
    audit_res = dep_svc.audit_path(repo, recursive=True)
    assert audit_res.packages_scanned == 9
    assert len(audit_res.source_files) == 9
    assert audit_res.unpatched_count == 1
    assert any(
        "pip install --upgrade" in c and "requests>=2.32.0" in c for c in audit_res.upgrade_commands
    )
    req_vuln = next(v for v in audit_res.vulnerabilities if v.package == "requests")
    assert req_vuln.cvss_score == 9.8
    assert req_vuln.severity == "CRITICAL"
    assert req_vuln.source_file is not None and req_vuln.source_file.endswith("uv.lock")

    sarif_doc = json.loads(render_dependency_sarif(audit_res))
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif_doc["runs"][0]["results"]
    ]
    assert any(u.endswith("uv.lock") for u in uris)
    assert build_upgrade_commands(
        [
            DependencyVuln(
                package="axios",
                version="0.21.1",
                ecosystem="npm",
                vuln_id="V1",
                fixed_versions=["1.6.0"],
            )
        ]
    ) == ["npm install axios@1.6.0"]
