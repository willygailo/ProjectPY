"""CSP3 static analyzer detecting script gadgets, JSONP CDN bypasses, and policy gaps."""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from s1shell.analyze.models import CSPAnalysisResult, CSPFinding
from s1shell.errors import ValidationError

_KNOWN_CSP_DIRECTIVES = frozenset(
    {
        "default-src",
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "style-src",
        "style-src-elem",
        "style-src-attr",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "child-src",
        "worker-src",
        "manifest-src",
        "prefetch-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
        "sandbox",
        "report-uri",
        "report-to",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
        "require-trusted-types-for",
        "trusted-types",
        "navigate-to",
        "plugin-types",
        "fenced-frame-src",
    }
)

# Public CDNs, JSONP hosts, and user-content platforms commonly documented as CSP script bypasses.
_CSP_BYPASS_DOMAINS: dict[str, str] = {
    "ajax.googleapis.com": "Hosts legacy AngularJS / JSONP endpoints usable to bypass script-src",
    "cdnjs.cloudflare.com": "Hosts AngularJS / arbitrary library versions usable as script gadgets",
    "cdn.jsdelivr.net": "Serves arbitrary GitHub/npm user-controlled JavaScript packages",
    "unpkg.com": "Serves arbitrary npm packages including AngularJS and custom scripts",
    "raw.githubusercontent.com": "Serves arbitrary user-uploaded repository files",
    "gist.githubusercontent.com": "Serves arbitrary user-uploaded GitHub Gist scripts",
    "code.jquery.com": "Hosts legacy jQuery / script gadgets",
    "storage.googleapis.com": (
        "Shared public cloud storage bucket host (attacker-controlled buckets)"
    ),
    "s3.amazonaws.com": "Shared public S3 endpoint (attacker-controlled buckets)",
    "firebasestorage.googleapis.com": "Shared Firebase Storage host",
    "googleapis.com": "Broad Google APIs domain includes JSONP endpoints",
    "gstatic.com": "Broad Google static host includes Angular/script gadgets",
    "google.com": "Includes JSONP endpoints (/complete/search, /jsapi)",
    "accounts.google.com": "Includes JSONP/OAuth callback endpoints",
    "googletagmanager.com": "Broad GTM allowlist permits arbitrary container tags if misconfigured",
    "google-analytics.com": "Broad analytics host with legacy JSONP endpoints",
    "cloudfront.net": "Shared CDN domain (attacker-controlled distributions)",
    "azureedge.net": "Shared Azure CDN domain (attacker-controlled origins)",
    "blob.core.windows.net": "Shared Azure Blob host (attacker-controlled containers)",
    "firebaseapp.com": "Shared Firebase Hosting domain",
    "web.app": "Shared Firebase Hosting domain",
    "netlify.app": "Shared Netlify hosting domain",
    "vercel.app": "Shared Vercel hosting domain",
    "pages.dev": "Shared Cloudflare Pages domain",
    "github.io": "Shared GitHub Pages domain",
    "herokuapp.com": "Shared Heroku app domain",
    "appspot.com": "Shared Google App Engine domain",
    "dropboxusercontent.com": "Shared user-uploaded content host",
}

_NONCE_RE = re.compile(r"^'nonce-([^']+)'$", re.IGNORECASE)
_HASH_RE = re.compile(r"^'sha(?:256|384|512)-([^']+)'$", re.IGNORECASE)
_SEV_PENALTY = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _extract_host_from_source(source: str) -> str | None:
    cleaned = source.strip().lower()
    if not cleaned or cleaned.startswith("'") or cleaned.endswith(":"):
        return None
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/", 1)[0].split(":", 1)[0].strip()
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return cleaned if "." in cleaned else None


def _grade_from_score(score: int, findings: list[CSPFinding]) -> str:
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
        return "D"
    if any(f.severity == "HIGH" for f in findings) and order.index(grade) < order.index("C"):
        return "C"
    return grade


def extract_csp_from_artifact(path: Path) -> tuple[str, str]:
    """Load a raw CSP string from a saved S1shell `profile.json`/`assess.json` or text file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError(f"Failed to read CSP input '{path}': {exc}") from exc

    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError as exc:
            raise ValidationError(f"Invalid JSON in '{path}': {exc}") from exc
        if isinstance(data, dict):
            prof = data.get("profile") if data.get("artifact_type") == "assess_report" else data
            if isinstance(prof, dict):
                hdrs = prof.get("headers")
                if isinstance(hdrs, dict):
                    for item in hdrs.get("security_headers") or []:
                        if (
                            isinstance(item, dict)
                            and str(item.get("header") or "").lower() == "content-security-policy"
                            and item.get("value")
                        ):
                            return str(item["value"]), str(path)
                for h_name, h_val in prof.get("raw_headers") or []:
                    if str(h_name).lower() == "content-security-policy" and h_val:
                        return str(h_val), str(path)
        raise ValidationError(f"No Content-Security-Policy header found inside '{path}'.")

    # Allow pasting "Content-Security-Policy: ..." header line directly
    if ":" in stripped and stripped.lower().startswith("content-security-policy:"):
        stripped = stripped.split(":", 1)[1].strip()
    if not stripped:
        raise ValidationError(f"CSP input file '{path}' is empty.")
    return stripped, str(path)


def analyze_csp(policy: str, *, source: str = "inline") -> CSPAnalysisResult:
    """Perform comprehensive CSP3 static security evaluation and generate a hardened policy."""
    raw = policy.strip()
    if raw.lower().startswith("content-security-policy:"):
        raw = raw.split(":", 1)[1].strip()
    if not raw:
        raise ValidationError("Content-Security-Policy string cannot be empty.")

    directives: dict[str, list[str]] = {}
    duplicates: list[str] = []
    unknowns: list[str] = []
    findings: list[CSPFinding] = []
    bypass_hosts: list[str] = []

    for part in raw.split(";"):
        cleaned = part.strip()
        if not cleaned:
            continue
        tokens = cleaned.split()
        dname = tokens[0].lower()
        sources = tokens[1:]
        if dname in directives:
            if dname not in duplicates:
                duplicates.append(dname)
            findings.append(
                CSPFinding(
                    id="CSP-012",
                    severity="MEDIUM",
                    directive=dname,
                    title=f"Duplicate `{dname}` directive (second occurrence ignored by browsers)",
                    evidence=cleaned[:140],
                    remediation=f"Merge all `{dname}` sources into a single directive.",
                )
            )
            continue
        directives[dname] = sources
        if dname not in _KNOWN_CSP_DIRECTIVES:
            unknowns.append(dname)
            close = difflib.get_close_matches(dname, sorted(_KNOWN_CSP_DIRECTIVES), n=1, cutoff=0.6)
            hint = f" (did you mean `{close[0]}`?)" if close else ""
            findings.append(
                CSPFinding(
                    id="CSP-013",
                    severity="MEDIUM",
                    directive=dname,
                    title=f"Unknown or misspelled CSP directive `{dname}`{hint}",
                    evidence=cleaned[:140],
                    remediation=(
                        "Fix the directive spelling; browsers silently ignore unrecognized "
                        "directives."
                    ),
                )
            )

    script_dir = "script-src" if "script-src" in directives else "default-src"
    script_sources = directives.get("script-src", directives.get("default-src", []))
    script_low = [s.lower() for s in script_sources]

    nonces = [m.group(1) for s in script_sources if (m := _NONCE_RE.match(s))]
    hashes = [m.group(1) for s in script_sources if (m := _HASH_RE.match(s))]
    has_nonce_or_hash = bool(nonces or hashes)
    has_strict_dynamic = "'strict-dynamic'" in script_low

    if not script_sources:
        findings.append(
            CSPFinding(
                id="CSP-001",
                severity="HIGH",
                directive="script-src",
                title="Missing `script-src` and `default-src` fallback",
                evidence="No script execution restriction defined.",
                remediation=(
                    "Define `default-src 'self'` and an explicit nonce/hash-based `script-src`."
                ),
                cwe="CWE-79",
            )
        )
    else:
        if "'unsafe-inline'" in script_low and not has_nonce_or_hash:
            findings.append(
                CSPFinding(
                    id="CSP-002",
                    severity="HIGH",
                    directive=script_dir,
                    title=f"`{script_dir}` allows `'unsafe-inline'` without nonce or hash",
                    evidence=" ".join(script_sources)[:140],
                    remediation=(
                        "Remove `'unsafe-inline'` or pair with cryptographically random "
                        "`'nonce-...'` + `'strict-dynamic'`."
                    ),
                    cwe="CWE-79",
                )
            )
        if "'unsafe-eval'" in script_low:
            findings.append(
                CSPFinding(
                    id="CSP-003",
                    severity="HIGH",
                    directive=script_dir,
                    title=f"`{script_dir}` permits dynamic code evaluation (`'unsafe-eval'`)",
                    evidence=" ".join(script_sources)[:140],
                    remediation=(
                        "Refactor `eval()`/`new Function()` usages and remove `'unsafe-eval'`."
                    ),
                    cwe="CWE-95",
                )
            )
        if "*" in script_low and not has_strict_dynamic:
            findings.append(
                CSPFinding(
                    id="CSP-004",
                    severity="HIGH",
                    directive=script_dir,
                    title=f"`{script_dir}` allows wildcard `*` script origins",
                    evidence=" ".join(script_sources)[:140],
                    remediation=(
                        "Replace `*` with explicit trusted origins or `'nonce-...' "
                        "'strict-dynamic'`."
                    ),
                    cwe="CWE-79",
                )
            )
        for bad_scheme in ("data:", "blob:", "http:", "https:"):
            if bad_scheme in script_low and not (bad_scheme == "https:" and has_strict_dynamic):
                sev = "HIGH" if bad_scheme in {"data:", "http:"} else "MEDIUM"
                findings.append(
                    CSPFinding(
                        id="CSP-005",
                        severity=sev,
                        directive=script_dir,
                        title=f"`{script_dir}` allows overly broad `{bad_scheme}` URI scheme",
                        evidence=f"{script_dir} contains `{bad_scheme}`",
                        remediation=f"Remove `{bad_scheme}` from `{script_dir}`.",
                        cwe="CWE-79",
                    )
                )

        for nval in nonces:
            if len(nval) < 16:
                findings.append(
                    CSPFinding(
                        id="CSP-011",
                        severity="MEDIUM",
                        directive=script_dir,
                        title="CSP script nonce is shorter than 128 bits (<16 chars)",
                        evidence=f"'nonce-{nval}' (length={len(nval)})",
                        remediation=(
                            "Generate at least 128 bits (16+ random bytes, base64-encoded) per "
                            "HTTP response."
                        ),
                        cwe="CWE-330",
                    )
                )

        if not has_strict_dynamic:
            for src in script_sources:
                host = _extract_host_from_source(src)
                if not host:
                    continue
                for bypass_dom, reason in _CSP_BYPASS_DOMAINS.items():
                    if host == bypass_dom or host.endswith("." + bypass_dom):
                        if host not in bypass_hosts:
                            bypass_hosts.append(host)
                            findings.append(
                                CSPFinding(
                                    id="CSP-006",
                                    severity="HIGH",
                                    directive=script_dir,
                                    title=(
                                        f"Allowlisted script host `{src}` is a known CSP "
                                        "bypass/gadget origin"
                                    ),
                                    evidence=reason,
                                    remediation=(
                                        f"Replace host allowlist `{src}` with per-request "
                                        "nonces/SHA-256 "
                                        "hashes + `'strict-dynamic'`, or self-host pinned assets."
                                    ),
                                    cwe="CWE-79",
                                )
                            )
                        break

    obj_sources = directives.get("object-src", directives.get("default-src", []))
    obj_low = [s.lower() for s in obj_sources]
    if "'none'" not in obj_low:
        findings.append(
            CSPFinding(
                id="CSP-007",
                severity="MEDIUM",
                directive="object-src",
                title="Missing `object-src 'none'` (plugin/Flash/PDF script execution surface)",
                evidence=f"object-src={directives.get('object-src', ['(unset)'])}",
                remediation=(
                    "Explicitly set `object-src 'none'` to disable legacy plugin execution."
                ),
            )
        )

    if "base-uri" not in directives:
        findings.append(
            CSPFinding(
                id="CSP-008",
                severity="MEDIUM" if has_nonce_or_hash else "LOW",
                directive="base-uri",
                title="Missing `base-uri` directive (relative script URL hijacking risk)",
                evidence="base-uri is not set (does not inherit from default-src).",
                remediation="Add `base-uri 'none'` or `base-uri 'self'`.",
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            CSPFinding(
                id="CSP-009",
                severity="LOW",
                directive="frame-ancestors",
                title="Missing `frame-ancestors` clickjacking defense",
                evidence="frame-ancestors is not set (does not inherit from default-src).",
                remediation=(
                    "Add `frame-ancestors 'none'` (or `'self'`) to block cross-origin framing."
                ),
                cwe="CWE-1021",
            )
        )
    elif "*" in [s.lower() for s in directives["frame-ancestors"]]:
        findings.append(
            CSPFinding(
                id="CSP-009",
                severity="MEDIUM",
                directive="frame-ancestors",
                title="`frame-ancestors` allows wildcard `*` framing",
                evidence=" ".join(directives["frame-ancestors"]),
                remediation=(
                    "Restrict `frame-ancestors` to `'none'`, `'self'`, or explicit trusted origins."
                ),
                cwe="CWE-1021",
            )
        )

    if "form-action" not in directives:
        findings.append(
            CSPFinding(
                id="CSP-010",
                severity="LOW",
                directive="form-action",
                title="Missing `form-action` directive (form submission destination unrestricted)",
                evidence="form-action does not inherit from default-src.",
                remediation=(
                    "Add `form-action 'self'` (plus explicit payment/IdP endpoints if needed)."
                ),
            )
        )

    if "require-trusted-types-for" not in directives:
        findings.append(
            CSPFinding(
                id="CSP-014",
                severity="INFO",
                directive="require-trusted-types-for",
                title="DOM XSS Trusted Types enforcement not configured",
                evidence=(
                    "Consider `require-trusted-types-for 'script'` for modern SPA DOM XSS defense."
                ),
                remediation="Pilot `require-trusted-types-for 'script'` in Report-Only mode first.",
            )
        )

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.id, f.directive))
    penalty = sum(_SEV_PENALTY.get(f.severity, 0) for f in findings)
    score = max(0, 100 - min(penalty, 100))
    grade = _grade_from_score(score, findings)

    recommended = (
        "default-src 'self'; "
        "script-src 'nonce-<RANDOM_128BIT>' 'strict-dynamic'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )

    return CSPAnalysisResult(
        raw_policy=raw,
        source=source,
        score=score,
        grade=grade,
        directives=directives,
        duplicate_directives=duplicates,
        unknown_directives=unknowns,
        bypass_hosts=bypass_hosts,
        findings=findings,
        recommended_policy=recommended,
    )
