"""Offline & passive DNS Email Authentication & Spoofing Defense Auditor (SPF/DMARC/DKIM)."""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from s1shell.analyze.models import EmailAuthAnalysisResult, EmailAuthFinding
from s1shell.errors import ValidationError
from s1shell.profile.dns_check import (
    DnspythonResolver,
    RecordResolver,
    analyze_spf_recursive,
    count_spf_lookups,
)

_DMARC_PAIR_RE = re.compile(r"\b([a-z]{1,6})\s*=\s*([^;]+)", re.IGNORECASE)
_SPF_IP4_RE = re.compile(r"^[+]?ip4:([^\s]+)$", re.IGNORECASE)
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_PENALTY = {"CRITICAL": 35, "HIGH": 22, "MEDIUM": 10, "LOW": 4, "INFO": 0}


def _unquote_txt(record: str) -> str:
    return "".join(p.strip('"') for p in record.split('" "')).strip('"').strip()


def _parse_kv_record(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for k, v in _DMARC_PAIR_RE.findall(record):
        tags[k.strip().lower()] = v.strip()
    return tags


def _compute_spf_blast_radius(spf_record: str) -> int:
    total_ips = 0
    for tok in spf_record.split():
        m = _SPF_IP4_RE.match(tok)
        if not m:
            continue
        raw = m.group(1)
        try:
            net = ipaddress.IPv4Network(raw if "/" in raw else f"{raw}/32", strict=False)
            total_ips += net.num_addresses
        except ValueError:
            continue
    return total_ips


def _analyze_dkim_record(
    dkim_record: str,
    *,
    selector: str | None,
) -> tuple[str | None, int | None, list[EmailAuthFinding]]:
    findings: list[EmailAuthFinding] = []
    tags = _parse_kv_record(dkim_record)
    key_type = tags.get("k", "rsa").lower()
    pub_b64 = re.sub(r"\s+", "", tags.get("p", ""))
    flags = tags.get("t", "").lower()

    if "y" in flags.split(":"):
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DKIM-TEST",
                severity="MEDIUM",
                protocol="dkim",
                title=f"DKIM selector `{selector or 'supplied'}` is in testing mode (`t=y`)",
                evidence=dkim_record[:120],
                remediation="Remove `t=y` once DKIM signing is validated in production.",
            )
        )

    if not pub_b64:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DKIM-REVOKED",
                severity="INFO",
                protocol="dkim",
                title=(
                    f"DKIM key for selector `{selector or 'supplied'}` is explicitly revoked (`p=`)"
                ),
                evidence="Empty `p=` tag revokes signing authority for this selector.",
                remediation=(
                    "No action needed if intentionally revoked; otherwise publish a 2048-bit key."
                ),
            )
        )
        return key_type, 0, findings

    padded = pub_b64 + "=" * ((4 - len(pub_b64) % 4) % 4)
    try:
        der_bytes = base64.b64decode(padded, validate=False)
    except Exception:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DKIM-PARSE",
                severity="MEDIUM",
                protocol="dkim",
                title="DKIM public key (`p=`) is not valid Base64",
                evidence=pub_b64[:60],
                remediation="Re-export a clean Base64 DER SubjectPublicKeyInfo value for `p=`.",
            )
        )
        return key_type, None, findings

    if key_type == "ed25519":
        bits = len(der_bytes) * 8
        if bits < 256:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DKIM-WEAK",
                    severity="HIGH",
                    protocol="dkim",
                    title=f"Invalid Ed25519 DKIM key length ({bits} bits)",
                    evidence=f"Expected 256-bit Ed25519 public key, got {bits} bits.",
                    remediation="Publish a valid RFC 8463 256-bit Ed25519 DKIM public key.",
                    cwe="CWE-326",
                )
            )
        return "Ed25519", bits, findings

    try:
        pub_key = serialization.load_der_public_key(der_bytes)
    except Exception:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DKIM-PARSE",
                severity="LOW",
                protocol="dkim",
                title="Could not decode DKIM DER SubjectPublicKeyInfo payload",
                evidence=f"decoded_bytes={len(der_bytes)}",
                remediation=(
                    "Verify the DKIM TXT `p=` field matches a valid DER-encoded public key."
                ),
            )
        )
        return key_type.upper(), None, findings

    if isinstance(pub_key, rsa.RSAPublicKey):
        bits = pub_key.key_size
        if bits < 1024:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DKIM-WEAK",
                    severity="CRITICAL",
                    protocol="dkim",
                    title=f"Critically weak {bits}-bit RSA DKIM key (trivially factorable)",
                    evidence=f"selector={selector or 'inline'}, RSA-{bits}",
                    remediation="Rotate immediately to a 2048-bit RSA or Ed25519 DKIM key.",
                    cwe="CWE-326",
                )
            )
        elif bits < 2048:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DKIM-WEAK",
                    severity="MEDIUM",
                    protocol="dkim",
                    title=f"Legacy {bits}-bit RSA DKIM key (< 2048 bits recommended)",
                    evidence=f"selector={selector or 'inline'}, RSA-{bits}",
                    remediation="Upgrade DKIM selector to a 2048-bit RSA (or Ed25519) key.",
                    cwe="CWE-326",
                )
            )
        return "RSA", bits, findings
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, findings
    return type(pub_key).__name__, None, findings


def analyze_email_auth(
    domain: str,
    *,
    spf_record: str | None = None,
    dmarc_record: str | None = None,
    dkim_record: str | None = None,
    dkim_selector: str | None = None,
    offline: bool = False,
    timeout: float = 5.0,
    resolver_factory: Callable[[], RecordResolver] | None = None,
) -> EmailAuthAnalysisResult:
    """Audit SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI anti-spoofing defenses."""
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain or "/" in clean_domain or " " in clean_domain:
        raise ValidationError(f"Invalid domain '{domain}' for email authentication analysis.")

    has_manual = any(x is not None for x in (spf_record, dmarc_record, dkim_record))
    is_offline = offline or has_manual

    spf = spf_record.strip() if spf_record else None
    dmarc = dmarc_record.strip() if dmarc_record else None
    dkim = dkim_record.strip() if dkim_record else None
    mta_sts_present: bool | None = None
    tls_rpt_present: bool | None = None
    bimi_present: bool | None = None
    spf_lookups = 0
    spf_void = 0
    spf_rec_issues: list[str] = []

    if not is_offline:
        client = (
            resolver_factory()
            if resolver_factory is not None
            else DnspythonResolver(timeout=timeout)
        )

        def _q(name: str) -> list[str]:
            try:
                return [_unquote_txt(t) for t in client.resolve(name, "TXT", lifetime=timeout)]
            except Exception:
                return []

        if spf is None:
            spf = next((t for t in _q(clean_domain) if t.lower().startswith("v=spf1")), None)
        if dmarc is None:
            dmarc = next(
                (t for t in _q(f"_dmarc.{clean_domain}") if t.lower().startswith("v=dmarc1")),
                None,
            )
        if dkim is None and dkim_selector:
            sel = dkim_selector.strip().rstrip(".")
            dkim = next(
                (t for t in _q(f"{sel}._domainkey.{clean_domain}") if "p=" in t.lower()),
                None,
            )
        mta_sts_present = any("v=stsv1" in t.lower() for t in _q(f"_mta-sts.{clean_domain}"))
        tls_rpt_present = any("v=tlsrptv1" in t.lower() for t in _q(f"_smtp._tls.{clean_domain}"))
        bimi_present = any("v=bimi1" in t.lower() for t in _q(f"default._bimi.{clean_domain}"))
        if spf:
            spf_lookups, spf_void, spf_rec_issues = analyze_spf_recursive(
                client, clean_domain, spf, timeout=timeout
            )
    elif spf:
        spf_lookups = count_spf_lookups(spf)

    findings: list[EmailAuthFinding] = []
    all_qual: str | None = None
    blast_radius = 0

    # --- 1. SPF Analysis ---
    if not spf:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-SPF-MISSING",
                severity="HIGH",
                protocol="spf",
                title="Missing SPF (`v=spf1`) TXT record",
                evidence=f"No SPF record found for {clean_domain}.",
                remediation=(
                    f'Publish `{clean_domain}. IN TXT "v=spf1 -all"` (or explicit authorized '
                    "senders)."
                ),
            )
        )
    else:
        tokens = spf.split()
        low_tokens = [t.lower() for t in tokens]
        for cand in ("-all", "~all", "?all", "+all", "all"):
            if cand in low_tokens:
                all_qual = "+all" if cand == "all" else cand
                break

        blast_radius = _compute_spf_blast_radius(spf)
        if all_qual == "+all":
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-PASSALL",
                    severity="CRITICAL",
                    protocol="spf",
                    title=(
                        "SPF ends with `+all` (authorizes every IP on the internet to spoof mail)"
                    ),
                    evidence=spf[:160],
                    remediation=(
                        "Replace `+all` with `-all` (hardfail) or `~all` during transition."
                    ),
                )
            )
        elif all_qual == "?all" or all_qual is None:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-WEAK",
                    severity="HIGH",
                    protocol="spf",
                    title=f"SPF uses weak/missing terminator (`{all_qual or 'none'}`)",
                    evidence=spf[:160],
                    remediation=(
                        "End the SPF record with `-all` (hardfail) or `~all` paired with DMARC "
                        "`p=reject`."
                    ),
                )
            )
        elif all_qual == "~all":
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-SOFTFAIL",
                    severity="LOW",
                    protocol="spf",
                    title="SPF uses softfail (`~all`) instead of strict hardfail (`-all`)",
                    evidence=spf[:160],
                    remediation=(
                        "Enforce DMARC `p=reject` and transition SPF to `-all` once senders are "
                        "verified."
                    ),
                )
            )

        if any(t.lstrip("+-~?").startswith("ptr") for t in low_tokens):
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-PTR",
                    severity="LOW",
                    protocol="spf",
                    title="SPF uses deprecated `ptr` mechanism (RFC 7208 Section 5.5)",
                    evidence=spf[:160],
                    remediation=(
                        "Replace `ptr` with explicit `ip4:`/`ip6:` or `include:` mechanisms."
                    ),
                )
            )

        if spf_lookups > 10:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-LOOKUPS",
                    severity="HIGH",
                    protocol="spf",
                    title=(
                        f"SPF exceeds RFC 7208 10-DNS-lookup limit ({spf_lookups} lookups -> "
                        "PermError)"
                    ),
                    evidence=f"lookups={spf_lookups}, void={spf_void}",
                    remediation=(
                        "Flatten or consolidate `include:` chains so total DNS lookups stay <= 10."
                    ),
                )
            )
        if spf_void > 2:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-VOID",
                    severity="MEDIUM",
                    protocol="spf",
                    title=f"SPF triggers {spf_void} void lookups (RFC 7208 max is 2)",
                    evidence="; ".join(spf_rec_issues[:2]) or f"void_lookups={spf_void}",
                    remediation="Remove stale/NXDOMAIN `include:` targets from SPF.",
                )
            )
        if blast_radius >= 65_536:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-SPF-BLAST",
                    severity="MEDIUM",
                    protocol="spf",
                    title=(
                        f"SPF `ip4:` CIDRs authorize a very large blast radius ({blast_radius:,} "
                        "IPs)"
                    ),
                    evidence=spf[:160],
                    remediation=(
                        "Tighten `ip4:` ranges strictly to dedicated outbound MTA IP addresses."
                    ),
                )
            )

    # --- 2. DMARC Analysis ---
    dmarc_tags = _parse_kv_record(dmarc) if dmarc else {}
    if not dmarc:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DMARC-MISSING",
                severity="HIGH",
                protocol="dmarc",
                title="Missing DMARC (`_dmarc`) policy record",
                evidence=f"No DMARC TXT record for _dmarc.{clean_domain}.",
                remediation=(
                    f'Publish `_dmarc.{clean_domain}. IN TXT "v=DMARC1; p=quarantine; sp=reject; '
                    f'adkim=s; aspf=s; rua=mailto:dmarc@{clean_domain}"`.'
                ),
            )
        )
    else:
        policy = dmarc_tags.get("p", "").lower()
        sub_policy = dmarc_tags.get("sp", policy).lower()
        pct_raw = dmarc_tags.get("pct", "100")
        try:
            pct = int(pct_raw)
        except ValueError:
            pct = 100

        if policy == "none" or not policy:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-NONE",
                    severity="HIGH",
                    protocol="dmarc",
                    title=f"DMARC policy is monitoring-only (`p={policy or 'missing'}`)",
                    evidence=dmarc[:160],
                    remediation=(
                        "Advance DMARC policy from `p=none` to `p=quarantine` then `p=reject`."
                    ),
                )
            )
        elif policy == "quarantine":
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-QUAR",
                    severity="LOW",
                    protocol="dmarc",
                    title=(
                        "DMARC uses `p=quarantine` (consider `p=reject` for full spoofing "
                        "prevention)"
                    ),
                    evidence=dmarc[:160],
                    remediation=(
                        "Move to `p=reject` once aggregate (`rua`) reports confirm clean alignment."
                    ),
                )
            )

        if sub_policy == "none" and policy in {"quarantine", "reject"}:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-SUB",
                    severity="MEDIUM",
                    protocol="dmarc",
                    title="DMARC subdomain policy (`sp=none`) leaves all subdomains spoofable",
                    evidence=dmarc[:160],
                    remediation="Set `sp=reject` to block spoofing of unused subdomains.",
                )
            )

        if pct < 100:
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-PCT",
                    severity="MEDIUM",
                    protocol="dmarc",
                    title=f"DMARC applies only to {pct}% of messages (`pct={pct}`)",
                    evidence=dmarc[:160],
                    remediation="Increase `pct=100` (or omit `pct`) for full domain enforcement.",
                )
            )

        if not dmarc_tags.get("rua"):
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-RUA",
                    severity="LOW",
                    protocol="dmarc",
                    title="DMARC omits aggregate reporting URI (`rua=`)",
                    evidence=dmarc[:160],
                    remediation=(
                        f"Add `rua=mailto:dmarc@{clean_domain}` for spoofing telemetry visibility."
                    ),
                )
            )

        if (
            dmarc_tags.get("adkim", "r").lower() != "s"
            or dmarc_tags.get("aspf", "r").lower() != "s"
        ):
            findings.append(
                EmailAuthFinding(
                    id="EMAIL-DMARC-ALIGN",
                    severity="INFO",
                    protocol="dmarc",
                    title="DMARC uses relaxed identifier alignment (`adkim=r` / `aspf=r`)",
                    evidence=(
                        f"adkim={dmarc_tags.get('adkim', 'r')}, aspf={dmarc_tags.get('aspf', 'r')}"
                    ),
                    remediation=(
                        "Use strict alignment (`adkim=s; aspf=s`) for high-sensitivity domains."
                    ),
                )
            )

    # --- 3. DKIM Analysis ---
    dkim_key_type: str | None = None
    dkim_key_bits: int | None = None
    if dkim:
        dkim_key_type, dkim_key_bits, dkim_findings = _analyze_dkim_record(
            dkim, selector=dkim_selector
        )
        findings.extend(dkim_findings)
    elif dkim_selector and not is_offline:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-DKIM-MISSING",
                severity="MEDIUM",
                protocol="dkim",
                title=(
                    "No DKIM TXT record found for selector "
                    f"`{dkim_selector}._domainkey.{clean_domain}`"
                ),
                evidence=f"{dkim_selector}._domainkey.{clean_domain}",
                remediation=(
                    "Verify the active DKIM selector and publish a 2048-bit RSA or Ed25519 key."
                ),
            )
        )

    # --- 4. Transport & Brand Signals (Live DNS) ---
    if mta_sts_present is False:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-MTASTS-MISSING",
                severity="LOW",
                protocol="mta-sts",
                title="Missing MTA-STS (`_mta-sts`) inbound TLS policy",
                evidence=f"_mta-sts.{clean_domain} not published.",
                remediation=(
                    f'Publish `_mta-sts.{clean_domain}. IN TXT "v=STSv1; id=20260101"` and '
                    "`/.well-known/mta-sts.txt`."
                ),
            )
        )
    if tls_rpt_present is False:
        findings.append(
            EmailAuthFinding(
                id="EMAIL-TLSRPT-MISSING",
                severity="INFO",
                protocol="tls-rpt",
                title="Missing SMTP TLS-RPT (`_smtp._tls`) failure reporting",
                evidence=f"_smtp._tls.{clean_domain} not published.",
                remediation=(
                    f'Publish `_smtp._tls.{clean_domain}. IN TXT "v=TLSRPTv1; '
                    f'rua=mailto:tlsrpt@{clean_domain}"`.'
                ),
            )
        )

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.id))
    penalty = sum(_SEV_PENALTY.get(f.severity, 0) for f in findings)
    score = max(0, 100 - min(penalty, 100))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"

    order = ["A", "B", "C", "D", "F"]
    if any(f.severity == "CRITICAL" for f in findings) and order.index(grade) < order.index("D"):
        grade = "D"
    elif any(f.severity == "HIGH" for f in findings) and order.index(grade) < order.index("C"):
        grade = "C"

    if any(f.severity == "CRITICAL" for f in findings):
        risk = "CRITICAL"
    elif any(f.severity == "HIGH" for f in findings):
        risk = "HIGH"
    elif any(f.severity == "MEDIUM" for f in findings) or score < 75:
        risk = "MODERATE"
    elif findings:
        risk = "LOW"
    else:
        risk = "MINIMAL"

    recommended = [
        f'{clean_domain}.  IN  TXT  "v=spf1 -all"  ; add authorized mailers before -all',
        f'_dmarc.{clean_domain}.  IN  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; '
        f'rua=mailto:dmarc@{clean_domain}"',
        f'_mta-sts.{clean_domain}.  IN  TXT  "v=STSv1; id=20260101"',
        f'_smtp._tls.{clean_domain}.  IN  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@{clean_domain}"',
    ]

    return EmailAuthAnalysisResult(
        domain=clean_domain,
        mode="offline" if is_offline else "live_dns",
        score=score,
        grade=grade,
        spoofing_risk=risk,
        spf_record=spf,
        spf_all_qualifier=all_qual,
        spf_lookup_count=spf_lookups,
        spf_void_lookups=spf_void,
        spf_ipv4_blast_radius=blast_radius,
        dmarc_record=dmarc,
        dmarc_tags=dmarc_tags,
        dkim_selector=dkim_selector,
        dkim_record=dkim,
        dkim_key_type=dkim_key_type,
        dkim_key_bits=dkim_key_bits,
        mta_sts_present=mta_sts_present,
        tls_rpt_present=tls_rpt_present,
        bimi_present=bimi_present,
        findings=findings,
        recommended_records=recommended,
    )
