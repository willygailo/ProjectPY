"""Offline repository, file, and git-diff secret & credential exposure detector."""

from __future__ import annotations

import fnmatch
import hashlib
import math
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from s1shell.errors import ValidationError
from s1shell.scan.models import SecretFinding, SecretScanResult

_MAX_FILE_BYTES_DEFAULT = 2 * 1024 * 1024  # 2 MiB
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "target",
        ".tox",
        ".eggs",
        "htmlcov",
        "vendor",
    }
)

_SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".svg",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".whl",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".sqlite",
        ".db",
        ".lock",
    }
)

_IGNORE_MARKER_RE = re.compile(r"(?:s1shell:ignore|noscan|gitleaks:allow)", re.IGNORECASE)

_PLACEHOLDER_MARKERS = (
    "example",
    "changeme",
    "replace_me",
    "replaceme",
    "your_",
    "your-",
    "dummy",
    "placeholder",
    "redacted",
    "test_key",
    "fake_",
    "sample",
    "xxxxxxx",
    "00000000",
    "11111111",
    "12345678",
    "abcdef",
    "not-a-real",
    "insert_",
    "<your",
)


@dataclass(frozen=True)
class _SecretRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    remediation: str
    min_entropy: float = 0.0
    group: int = 1
    cwe: str = "CWE-798"


_SECRET_RULES: tuple[_SecretRule, ...] = (
    _SecretRule(
        rule_id="SEC-AWS-001",
        title="AWS Access Key ID exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        remediation=(
            "Revoke the IAM access key immediately, audit CloudTrail, and use IAM roles/OIDC."
        ),
    ),
    _SecretRule(
        rule_id="SEC-AWS-002",
        title="AWS Secret Access Key assignment exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        min_entropy=3.8,
        remediation=(
            "Rotate the AWS IAM credential immediately and migrate secrets to Secrets Manager."
        ),
    ),
    _SecretRule(
        rule_id="SEC-GCP-001",
        title="Google Cloud / Firebase API key exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        remediation=(
            "Restrict API key usage by referrer/IP/API scope or rotate it in Google Cloud Console."
        ),
    ),
    _SecretRule(
        rule_id="SEC-GCP-002",
        title="GCP Service Account private key JSON exposed",
        severity="CRITICAL",
        pattern=re.compile(r'("private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----)'),
        remediation=(
            "Delete the compromised service account key and adopt Workload Identity Federation."
        ),
    ),
    _SecretRule(
        rule_id="SEC-AZ-001",
        title="Azure Storage Account connection string exposed",
        severity="CRITICAL",
        pattern=re.compile(r"(AccountKey=[A-Za-z0-9+/]{60,90}==)"),
        min_entropy=3.5,
        remediation=(
            "Regenerate the Azure Storage Account key and switch to Microsoft Entra ID RBAC."
        ),
    ),
    _SecretRule(
        rule_id="SEC-GH-001",
        title="GitHub Personal Access or OAuth token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
        min_entropy=3.0,
        remediation=(
            "Revoke the token in GitHub Settings -> Developer settings and use short-lived OIDC "
            "tokens."
        ),
    ),
    _SecretRule(
        rule_id="SEC-GL-001",
        title="GitLab Personal or Deploy token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(gl(?:pat|dt|rt)-[A-Za-z0-9_-]{20,})\b"),
        min_entropy=3.0,
        remediation="Revoke the GitLab token immediately and use masked CI/CD variables.",
    ),
    _SecretRule(
        rule_id="SEC-AI-001",
        title="Anthropic API, User, or Admin key exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(sk-ant-(?:api|admin|usr)\d{0,2}-[A-Za-z0-9_-]{20,})\b"),
        min_entropy=3.2,
        remediation=(
            "Revoke the Anthropic key in Anthropic Console and inject it via environment/secret "
            "manager."
        ),
    ),
    _SecretRule(
        rule_id="SEC-AI-002",
        title="OpenAI API key exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})\b"),
        min_entropy=3.5,
        remediation=(
            "Revoke the OpenAI key in the OpenAI dashboard and move it to a vault/secret store."
        ),
    ),
    _SecretRule(
        rule_id="SEC-AI-003",
        title="Hugging Face access token exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b"),
        min_entropy=3.2,
        remediation=(
            "Revoke the Hugging Face token and scope replacements to read-only where possible."
        ),
    ),
    _SecretRule(
        rule_id="SEC-PAY-001",
        title="Stripe live secret or restricted key exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b"),
        min_entropy=3.0,
        remediation=(
            "Roll the Stripe live key immediately in the Stripe Dashboard and review API logs."
        ),
    ),
    _SecretRule(
        rule_id="SEC-SLACK-001",
        title="Slack API token exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
        remediation="Revoke the Slack token in Slack App Management and rotate OAuth credentials.",
    ),
    _SecretRule(
        rule_id="SEC-SLACK-002",
        title="Slack incoming webhook URL exposed",
        severity="MEDIUM",
        pattern=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})"
        ),
        remediation="Regenerate the Slack webhook URL and store it in runtime secrets.",
    ),
    _SecretRule(
        rule_id="SEC-DISC-001",
        title="Discord webhook URL exposed",
        severity="MEDIUM",
        pattern=re.compile(
            r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_-]{50,})"
        ),
        remediation="Delete and recreate the Discord webhook and keep it out of source control.",
    ),
    _SecretRule(
        rule_id="SEC-TG-001",
        title="Telegram Bot token exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b"),
        remediation="Revoke the Telegram bot token via @BotFather (/revoke) immediately.",
    ),
    _SecretRule(
        rule_id="SEC-MAIL-001",
        title="SendGrid API key exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{35,})\b"),
        remediation="Revoke the SendGrid API key and issue a least-privilege replacement.",
    ),
    _SecretRule(
        rule_id="SEC-MAIL-002",
        title="Mailgun API key exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(key-[0-9a-fA-F]{32})\b"),
        min_entropy=3.0,
        remediation="Rotate the Mailgun API key and store it outside the repository.",
    ),
    _SecretRule(
        rule_id="SEC-TWILIO-001",
        title="Twilio API key SID exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        min_entropy=3.0,
        remediation="Revoke the Twilio API key SID and rotate paired secrets.",
    ),
    _SecretRule(
        rule_id="SEC-PKG-001",
        title="npm authentication token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(npm_[A-Za-z0-9]{30,})\b"),
        min_entropy=3.2,
        remediation="Revoke the npm token (`npm token revoke`) and use trusted publishing/OIDC.",
    ),
    _SecretRule(
        rule_id="SEC-PKG-002",
        title="PyPI API token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{30,})\b"),
        remediation=(
            "Revoke the PyPI token immediately and switch to PyPI Trusted Publishers (OIDC)."
        ),
    ),
    _SecretRule(
        rule_id="SEC-PKG-003",
        title="Docker Hub personal access token exposed",
        severity="HIGH",
        pattern=re.compile(r"\b(dckr_pat_[A-Za-z0-9_-]{24,})\b"),
        remediation="Revoke the Docker Hub PAT and use short-lived CI credentials.",
    ),
    _SecretRule(
        rule_id="SEC-VAULT-001",
        title="HashiCorp Vault service token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(hvs\.[A-Za-z0-9_-]{24,})\b"),
        min_entropy=3.2,
        remediation="Revoke the Vault token (`vault token revoke`) and use AppRole/OIDC auth.",
    ),
    _SecretRule(
        rule_id="SEC-SHOP-001",
        title="Shopify Admin API access token exposed",
        severity="CRITICAL",
        pattern=re.compile(r"\b(shpat_[0-9a-fA-F]{32})\b"),
        min_entropy=3.0,
        remediation="Rotate the Shopify Admin API token immediately.",
    ),
    _SecretRule(
        rule_id="SEC-KEY-001",
        title="Private cryptographic key PEM block exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        remediation=(
            "Revoke/replace the private key and associated certificates; never commit keys to git."
        ),
        cwe="CWE-321",
    ),
    _SecretRule(
        rule_id="SEC-DB-001",
        title="Database or broker URI with embedded credentials exposed",
        severity="CRITICAL",
        pattern=re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://"
            r"[^/\s:@\"']+:[^/\s@\"']{4,}@[^\s\"'<>]+)"
        ),
        remediation=(
            "Rotate the database password and inject credentials via environment/secret manager."
        ),
    ),
    _SecretRule(
        rule_id="SEC-JWT-001",
        title="Hardcoded JSON Web Token (JWT) exposed",
        severity="MEDIUM",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        min_entropy=3.4,
        remediation=(
            "Remove hardcoded JWTs from source/config and rotate signing secrets if active."
        ),
    ),
    _SecretRule(
        rule_id="SEC-GEN-001",
        title="High-entropy hardcoded secret assignment",
        severity="HIGH",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|app[_-]?secret|"
            r"secret[_-]?key|jwt[_-]?secret|signing[_-]?key|private[_-]?key|auth[_-]?token|"
            r"access[_-]?token|db[_-]?password|database[_-]?password|master[_-]?password)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9+/=_.-]{16,128})['\"]"
        ),
        min_entropy=3.8,
        remediation=(
            "Remove the hardcoded secret, rotate the credential, and load it from a secret store."
        ),
    ),
)

_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def _redact_secret(raw: str) -> str:
    clean = raw.strip()
    if "-----BEGIN" in clean:
        return f"{clean[:32]}...[REDACTED]"
    if "://" in clean and "@" in clean:
        scheme_rest = clean.split("://", 1)
        creds_host = scheme_rest[1].split("@", 1)
        user = creds_host[0].split(":", 1)[0]
        return f"{scheme_rest[0]}://{user}:***@{creds_host[1]}"
    if len(clean) <= 10:
        return clean[:2] + "****"
    return f"{clean[:4]}****{clean[-4:]}"


def _is_placeholder(value: str, full_line: str) -> bool:
    low = value.lower()
    if low.startswith(("${", "$env", "env(", "os.environ", "process.env", "{{")):
        return True
    if any(m in low for m in _PLACEHOLDER_MARKERS):
        return True
    # Reject repeated single-character dummy strings (e.g. AAAAAAAA...)
    if len(set(value)) <= 3 and "-----BEGIN" not in value:
        return True
    # Reject regex definitions in scanner/detector code itself
    stripped_line = full_line.strip()
    return bool(
        stripped_line.startswith(("re.compile(", '("', "pattern=re.compile"))
        and ("\\b" in full_line or "[A-Za-z" in full_line or "[0-9" in full_line)
    )


def _is_binary_bytes(sample: bytes) -> bool:
    return b"\x00" in sample


def _load_gitignore_patterns(root: Path) -> list[str]:
    gi = root / ".gitignore"
    if not gi.is_file():
        return []
    patterns: list[str] = []
    try:
        for raw_line in gi.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            patterns.append(line.rstrip("/"))
    except OSError:
        return []
    return patterns


def _matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    parts = rel_path.split("/")
    for pat in patterns:
        if "/" in pat:
            if fnmatch.fnmatch(rel_path, pat.lstrip("/")) or fnmatch.fnmatch(
                rel_path, pat.lstrip("/") + "/*"
            ):
                return True
        elif any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
    return False


def _scan_text_lines(
    lines: list[tuple[int, str]],
    *,
    file_label: str,
    seen_fps: set[tuple[str, str, int]],
) -> tuple[list[SecretFinding], int]:
    findings: list[SecretFinding] = []
    suppressed = 0
    for line_no, raw_line in lines:
        if _IGNORE_MARKER_RE.search(raw_line):
            suppressed += 1
            continue
        if len(raw_line) > 8192 and "PRIVATE KEY" not in raw_line and "AKIA" not in raw_line:
            continue
        for rule in _SECRET_RULES:
            for match in rule.pattern.finditer(raw_line):
                secret_val = match.group(rule.group)
                if not secret_val or _is_placeholder(secret_val, raw_line):
                    continue
                ent = _shannon_entropy(secret_val)
                if rule.min_entropy > 0.0 and ent < rule.min_entropy:
                    continue
                fp_raw = f"{rule.rule_id}:{file_label}:{secret_val}"
                fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()[:16]
                dedup_key = (rule.rule_id, file_label, line_no)
                if dedup_key in seen_fps:
                    continue
                seen_fps.add(dedup_key)

                redacted = _redact_secret(secret_val)
                safe_ctx = raw_line.strip().replace(secret_val, redacted)[:160]
                findings.append(
                    SecretFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file_path=file_label,
                        line=line_no,
                        column=match.start(rule.group) + 1,
                        match_redacted=redacted,
                        fingerprint=fp,
                        entropy=ent,
                        remediation=rule.remediation,
                        context_line=safe_ctx,
                        cwe=rule.cwe,
                    )
                )
    return findings, suppressed


def _collect_git_diff_lines(
    repo_root: Path, *, staged: bool, diff_ref: str | None
) -> dict[str, list[tuple[int, str]]]:
    git_bin = shutil.which("git")
    if not git_bin:
        raise ValidationError("`git` executable not found on PATH.")
    cmd = [git_bin, "-C", str(repo_root), "diff", "--no-color", "-U0"]
    if staged:
        cmd.append("--cached")
    elif diff_ref:
        cmd.append(diff_ref)
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValidationError(f"Failed to execute git diff in '{repo_root}': {exc}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "git diff failed").strip()
        raise ValidationError(f"git diff failed in '{repo_root}': {err}")

    file_lines: dict[str, list[tuple[int, str]]] = {}
    cur_file: str | None = None
    cur_line = 0
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:].strip()
            file_lines.setdefault(cur_file, [])
            continue
        if line.startswith("+++ /dev/null"):
            cur_file = None
            continue
        hm = _HUNK_HEADER_RE.match(line)
        if hm:
            cur_line = int(hm.group(1))
            continue
        if cur_file and line.startswith("+") and not line.startswith("+++"):
            file_lines[cur_file].append((cur_line, line[1:]))
            cur_line += 1
    return file_lines


def scan_secrets(
    path: Path,
    *,
    respect_gitignore: bool = True,
    max_file_bytes: int = _MAX_FILE_BYTES_DEFAULT,
    git_staged: bool = False,
    git_diff: str | None = None,
) -> SecretScanResult:
    """Scan a local file, directory, or git diff for exposed secrets and credentials."""
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValidationError(f"Scan target does not exist: '{path}'.")

    findings: list[SecretFinding] = []
    seen_fps: set[tuple[str, str, int]] = set()
    files_scanned = 0
    files_skipped = 0
    suppressed_total = 0

    if git_staged or git_diff:
        repo_dir = resolved if resolved.is_dir() else resolved.parent
        diff_map = _collect_git_diff_lines(repo_dir, staged=git_staged, diff_ref=git_diff)
        for rel_file, added_lines in sorted(diff_map.items()):
            if not added_lines:
                continue
            files_scanned += 1
            f_list, sup = _scan_text_lines(added_lines, file_label=rel_file, seen_fps=seen_fps)
            findings.extend(f_list)
            suppressed_total += sup
        mode = "git-staged" if git_staged else f"git-diff:{git_diff}"
    elif resolved.is_file():
        mode = "filesystem"
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise ValidationError(f"Failed to read file '{path}': {exc}") from exc
        if len(raw) > max_file_bytes or _is_binary_bytes(raw[:8192]):
            files_skipped = 1
        else:
            files_scanned = 1
            text = raw.decode("utf-8", errors="replace")
            numbered = list(enumerate(text.splitlines(), start=1))
            f_list, sup = _scan_text_lines(numbered, file_label=str(path), seen_fps=seen_fps)
            findings.extend(f_list)
            suppressed_total += sup
    else:
        mode = "filesystem"
        gi_patterns = _load_gitignore_patterns(resolved) if respect_gitignore else []
        for item in sorted(resolved.rglob("*")):
            if not item.is_file():
                continue
            rel = item.relative_to(resolved)
            rel_str = rel.as_posix()
            if any(part in _SKIP_DIRS for part in rel.parts[:-1]):
                continue
            if item.suffix.lower() in _SKIP_EXTENSIONS:
                files_skipped += 1
                continue
            if gi_patterns and _matches_gitignore(rel_str, gi_patterns):
                files_skipped += 1
                continue
            try:
                size = item.stat().st_size
                if size == 0 or size > max_file_bytes:
                    files_skipped += 1
                    continue
                raw = item.read_bytes()
            except OSError:
                files_skipped += 1
                continue
            if _is_binary_bytes(raw[:8192]):
                files_skipped += 1
                continue
            files_scanned += 1
            text = raw.decode("utf-8", errors="replace")
            numbered = list(enumerate(text.splitlines(), start=1))
            f_list, sup = _scan_text_lines(numbered, file_label=rel_str, seen_fps=seen_fps)
            findings.extend(f_list)
            suppressed_total += sup

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.file_path, f.line, f.rule_id))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    highest = findings[0].severity if findings else None

    return SecretScanResult(
        target_path=str(path),
        scan_mode=mode,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        suppressed_count=suppressed_total,
        findings=findings,
        severity_counts=counts,
        highest_severity=highest,
    )
