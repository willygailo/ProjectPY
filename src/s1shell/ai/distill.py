"""Signal-first artifact distillation to maximize defensive context per LLM token."""

from __future__ import annotations

import json
from typing import Any


def _clip(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def _distill_profile(prof: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "artifact_type": prof.get("artifact_type", "profile_report"),
        "url": _clip(prof.get("url"), 240),
        "target": _clip(prof.get("target"), 240),
        "pinned_ip": prof.get("pinned_ip"),
    }
    proto = prof.get("protocol")
    if isinstance(proto, dict):
        out["protocol"] = {
            "status_code": proto.get("status_code"),
            "http_version": proto.get("http_version"),
            "alpn_protocol": proto.get("alpn_protocol"),
            "http3_advertised": proto.get("http3_advertised"),
            "redirect_location": _clip(proto.get("redirect_location"), 240),
            "allowed_methods": proto.get("allowed_methods", []),
            "risky_methods": proto.get("risky_methods", []),
        }
    tls = prof.get("tls")
    if isinstance(tls, dict) and tls.get("applicable"):
        out["tls"] = {
            "negotiated_version": tls.get("negotiated_version"),
            "supported_versions": tls.get("supported_versions", []),
            "cipher_suite": tls.get("cipher_suite"),
            "cipher_weaknesses": tls.get("cipher_weaknesses", []),
            "verified": tls.get("verified"),
            "verification_error": _clip(tls.get("verification_error"), 200),
            "issuer": _clip(tls.get("issuer"), 160),
            "days_remaining": tls.get("days_remaining"),
            "key_type": tls.get("key_type"),
            "key_size": tls.get("key_size"),
            "signature_algorithm": tls.get("signature_algorithm"),
            "is_self_signed": tls.get("is_self_signed"),
            "chain_length": tls.get("chain_length"),
            "chain_issues": tls.get("chain_issues", []),
        }
    dns = prof.get("dns")
    if isinstance(dns, dict):
        out["dns"] = {
            "a": dns.get("a", [])[:8],
            "aaaa": dns.get("aaaa", [])[:8],
            "cname": dns.get("cname", [])[:8],
            "caa": dns.get("caa", [])[:8],
            "spf": _clip(dns.get("spf"), 260),
            "spf_recursive_lookups": dns.get("spf_recursive_lookups"),
            "spf_void_lookups": dns.get("spf_void_lookups"),
            "spf_issues": dns.get("spf_issues", []),
            "dmarc": _clip(dns.get("dmarc"), 260),
            "dmarc_policy": dns.get("dmarc_policy"),
            "dnssec_present": dns.get("dnssec_present"),
            "dangling_cnames": dns.get("dangling_cnames", []),
        }
    headers = prof.get("headers")
    if isinstance(headers, dict):
        non_ok = [
            {
                "header": h.get("header"),
                "status": h.get("status"),
                "note": _clip(h.get("note"), 200),
            }
            for h in headers.get("security_headers", [])
            if isinstance(h, dict) and h.get("status") != "ok"
        ]
        insecure_cookies = [
            {
                "name": c.get("name"),
                "secure": c.get("secure"),
                "http_only": c.get("http_only"),
                "same_site": c.get("same_site"),
                "session": c.get("is_session_like"),
                "prefix_issues": c.get("prefix_issues", []),
            }
            for c in headers.get("cookies", [])
            if isinstance(c, dict)
            and (
                not c.get("secure")
                or not c.get("http_only")
                or not c.get("same_site")
                or c.get("prefix_issues")
            )
        ][:12]
        out["headers"] = {
            "non_ok_security_headers": non_ok,
            "banner_disclosures": headers.get("banner_disclosures", [])[:12],
            "debug_headers": headers.get("debug_headers", [])[:10],
            "cors_issues": headers.get("cors_issues", []),
            "cache_issues": headers.get("cache_issues", []),
            "insecure_cookies": insecure_cookies,
        }
    html = prof.get("html")
    if isinstance(html, dict) and html.get("analyzed"):
        out["html"] = {
            "title": _clip(html.get("title"), 200),
            "meta_generator": _clip(html.get("meta_generator"), 160),
            "detected_libraries": html.get("detected_libraries", [])[:15],
            "framework_hints": html.get("framework_hints", [])[:15],
            "mixed_content_count": len(html.get("mixed_content_urls", [])),
            "scripts_without_sri_count": len(html.get("external_scripts_without_sri", [])),
            "insecure_forms": html.get("insecure_forms", [])[:8],
            "leaked_secrets": html.get("leaked_secrets", [])[:10],
            "passive_jwts": html.get("passive_jwts", [])[:8],
            "source_maps": html.get("source_maps", [])[:8],
            "stack_traces": html.get("stack_traces", [])[:8],
        }
    wk = prof.get("well_known")
    if isinstance(wk, dict):
        out["well_known"] = {
            "security_txt_present": wk.get("security_txt_present"),
            "security_txt_expired": wk.get("security_txt_expired"),
            "robots_sensitive_hints": wk.get("robots_sensitive_hints", [])[:10],
            "oidc_present": wk.get("oidc_present"),
            "oidc_issues": wk.get("oidc_issues", []),
            "jwks_present": wk.get("jwks_present"),
            "jwks_issues": wk.get("jwks_issues", []),
        }
    return out


def _distill_cves(cve_blk: dict[str, Any]) -> dict[str, Any]:
    records = cve_blk.get("records", [])
    compact_recs: list[dict[str, Any]] = []
    if isinstance(records, list):
        for rec in records[:25]:
            if not isinstance(rec, dict):
                continue
            raw_cvss = rec.get("cvss")
            cvss: dict[str, Any] = raw_cvss if isinstance(raw_cvss, dict) else {}
            compact_recs.append(
                {
                    "cve_id": rec.get("cve_id"),
                    "severity": cvss.get("severity"),
                    "base_score": cvss.get("base_score"),
                    "in_kev": rec.get("in_kev", False),
                    "epss_score": rec.get("epss_score"),
                    "priority": rec.get("priority"),
                    "ghsa_id": rec.get("ghsa_id"),
                    "patched_versions": rec.get("patched_versions", [])[:4],
                    "description": str(rec.get("description") or "")[:240],
                }
            )
    return {
        "artifact_type": cve_blk.get("artifact_type", "cve_report"),
        "query": cve_blk.get("query"),
        "total_records": len(records) if isinstance(records, list) else 0,
        "records": compact_recs,
    }


def _distill_intel(intel: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "artifact_type": intel.get("artifact_type", "intel_report"),
        "indicator": intel.get("indicator"),
        "resolved_ip": intel.get("resolved_ip"),
        "sources_queried": intel.get("sources_queried", []),
    }
    if isinstance(intel.get("virustotal"), dict):
        vt = intel["virustotal"]
        out["virustotal"] = {
            "malicious": vt.get("malicious"),
            "suspicious": vt.get("suspicious"),
            "harmless": vt.get("harmless"),
            "reputation": vt.get("reputation"),
            "as_owner": vt.get("as_owner"),
            "categories": vt.get("categories", [])[:5],
        }
    if isinstance(intel.get("greynoise"), dict):
        gn = intel["greynoise"]
        out["greynoise"] = {
            "noise": gn.get("noise"),
            "riot": gn.get("riot"),
            "classification": gn.get("classification"),
            "name": gn.get("name"),
        }
    if isinstance(intel.get("urlscan"), dict):
        us = intel["urlscan"]
        out["urlscan"] = {
            "total_results": us.get("total_results"),
            "observed_ips": us.get("observed_ips", [])[:8],
            "observed_servers": us.get("observed_servers", [])[:8],
            "observed_asns": us.get("observed_asns", [])[:6],
        }
    if isinstance(intel.get("rdap"), dict):
        rd = intel["rdap"]
        out["rdap"] = {
            "registrar": rd.get("registrar"),
            "organization": rd.get("organization"),
            "transfer_locked": rd.get("transfer_locked"),
            "dnssec_signed": rd.get("dnssec_signed"),
            "days_until_expiry": rd.get("days_until_expiry"),
            "cidr": rd.get("cidr"),
        }
    return out


def distill_artifact(data: Any, *, max_chars: int = 12_000) -> Any:
    """Compact an S1shell JSON artifact prioritizing high-signal security telemetry."""
    if not isinstance(data, dict):
        return data

    # Fast path: if already compact enough, keep full fidelity
    serialized = json.dumps(data, separators=(",", ":"))
    if len(serialized) <= max_chars:
        return data

    atype = str(data.get("artifact_type") or "")
    if atype == "assess_report":
        raw_fp = data.get("fingerprint")
        fp: dict[str, Any] = raw_fp if isinstance(raw_fp, dict) else {}
        matches = [
            {
                "vendor": m.get("vendor"),
                "product": m.get("product"),
                "category": m.get("category"),
                "version": m.get("version"),
                "cpe": m.get("cpe"),
                "eol": m.get("eol", False),
                "eol_recommended": m.get("eol_recommended"),
            }
            for m in fp.get("matches", [])
            if isinstance(m, dict)
        ]
        distilled: dict[str, Any] = {
            "artifact_type": "assess_report",
            "url": data.get("url"),
            "target": data.get("target"),
            "pinned_ip": data.get("pinned_ip"),
            "preset": data.get("preset"),
            "posture": data.get("posture"),
            "findings": data.get("findings", [])[:60],
            "suppressed_count": len(data.get("suppressed_findings", []) or []),
            "fingerprint_matches": matches,
        }
        if isinstance(data.get("cve"), dict):
            distilled["cve"] = _distill_cves(data["cve"])
        if isinstance(data.get("intel"), dict):
            distilled["intel"] = _distill_intel(data["intel"])
        if isinstance(data.get("profile"), dict):
            distilled["profile_summary"] = _distill_profile(data["profile"])
        return distilled

    if atype == "profile_report":
        return _distill_profile(data)

    if atype == "cve_report":
        return _distill_cves(data)

    if atype == "intel_report":
        return _distill_intel(data)

    if atype == "dependency_audit_report":
        vulns = data.get("vulnerabilities", [])
        return {
            "artifact_type": "dependency_audit_report",
            "source_file": data.get("source_file"),
            "source_format": data.get("source_format"),
            "packages_scanned": data.get("packages_scanned"),
            "unpatched_count": data.get("unpatched_count"),
            "upgrade_commands": data.get("upgrade_commands", [])[:12],
            "vulnerabilities": vulns[:40] if isinstance(vulns, list) else [],
        }

    if atype == "ct_report":
        return {
            "artifact_type": "ct_report",
            "domain": data.get("domain"),
            "total_certificates": data.get("total_certificates"),
            "active_certificates": data.get("active_certificates"),
            "expired_certificates": data.get("expired_certificates"),
            "unique_subdomains": (data.get("unique_subdomains") or [])[:60],
            "wildcard_sans": (data.get("wildcard_sans") or [])[:25],
            "issuers": (data.get("issuers") or [])[:15],
        }

    return data
