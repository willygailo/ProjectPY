"""Local environment and workspace governance diagnostics (`s1shell doctor`)."""

from __future__ import annotations

import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from s1shell import __version__
from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig, classify_anthropic_key, mask_api_key
from s1shell.cve.cache import CVECache
from s1shell.errors import ValidationError
from s1shell.fingerprint.matcher import load_signatures
from s1shell.models import SCHEMA_VERSION, utc_now_iso
from s1shell.scope import ScopeManager


@dataclass(frozen=True)
class DoctorCheck:
    """Single local environment or state-file diagnostic check."""

    name: str
    status: str  # ok | warn | error
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    """Canonical diagnostic summary emitted by `s1shell doctor`."""

    home_dir: str
    checks: list[DoctorCheck] = field(default_factory=list)
    healthy: bool = True
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "doctor_report"


def _mode_str(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def run_doctor(cfg: RuntimeConfig) -> DoctorReport:
    """Run strictly local diagnostics across Python, permissions, scope, audit, cache, and sigs."""
    checks: list[DoctorCheck] = []

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(
        DoctorCheck(
            name="python",
            status="ok" if sys.version_info >= (3, 10) else "error",
            detail=f"Python {py_ver} (requires >= 3.10)",
        )
    )

    if cfg.home_dir.exists():
        mode = stat.S_IMODE(cfg.home_dir.stat().st_mode)
        perm_ok = (mode & 0o077) == 0
        checks.append(
            DoctorCheck(
                name="home_dir",
                status="ok" if perm_ok else "warn",
                detail=(f"{cfg.home_dir} exists (mode {_mode_str(cfg.home_dir)}; expected 0o700)"),
            )
        )
    else:
        checks.append(
            DoctorCheck(
                name="home_dir",
                status="ok",
                detail=f"{cfg.home_dir} not created yet (initialized on first write)",
            )
        )

    if cfg.scope_file.exists():
        try:
            entries = ScopeManager(cfg.scope_file).load()
            expired = sum(1 for e in entries if e.is_expired())
            excluded = sum(1 for e in entries if not e.is_expired() and e.exclude)
            active = len(entries) - expired - excluded
            mode_ok = (stat.S_IMODE(cfg.scope_file.stat().st_mode) & 0o077) == 0
            checks.append(
                DoctorCheck(
                    name="scope_file",
                    status="ok" if mode_ok else "warn",
                    detail=(
                        f"{cfg.scope_file}: {active} active, {excluded} excluded, "
                        f"{expired} expired (mode {_mode_str(cfg.scope_file)})"
                    ),
                )
            )
        except ValidationError as exc:
            checks.append(DoctorCheck(name="scope_file", status="error", detail=str(exc)))
    else:
        checks.append(
            DoctorCheck(
                name="scope_file",
                status="ok",
                detail=f"{cfg.scope_file} not present yet (no targets authorized)",
            )
        )

    if cfg.audit_log.exists():
        try:
            verify_res = AuditLogger(cfg.audit_log).verify()
            mode_ok = (stat.S_IMODE(cfg.audit_log.stat().st_mode) & 0o077) == 0
            if not verify_res.valid:
                checks.append(
                    DoctorCheck(
                        name="audit_log",
                        status="error",
                        detail=f"Integrity failure: {verify_res.errors[0]}",
                    )
                )
            else:
                checks.append(
                    DoctorCheck(
                        name="audit_log",
                        status="ok" if mode_ok else "warn",
                        detail=(
                            f"{cfg.audit_log}: {verify_res.total_entries} valid events "
                            f"({verify_res.chained_entries} hash-chained, mode "
                            f"{_mode_str(cfg.audit_log)})"
                        ),
                    )
                )
        except (OSError, ValidationError) as exc:
            checks.append(DoctorCheck(name="audit_log", status="error", detail=str(exc)))
    else:
        checks.append(
            DoctorCheck(
                name="audit_log",
                status="ok",
                detail=f"{cfg.audit_log} not created yet",
            )
        )

    if cfg.cache_db.exists():
        try:
            count = CVECache(cfg.cache_db).count()
            size_kb = cfg.cache_db.stat().st_size / 1024.0
            checks.append(
                DoctorCheck(
                    name="cve_cache",
                    status="ok",
                    detail=f"{cfg.cache_db}: {count} cached entries ({size_kb:.1f} KiB)",
                )
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(DoctorCheck(name="cve_cache", status="error", detail=str(exc)))
    else:
        checks.append(
            DoctorCheck(
                name="cve_cache",
                status="ok",
                detail=f"{cfg.cache_db} not initialized yet",
            )
        )

    try:
        bundled = load_signatures()
        all_sigs = load_signatures(extra_dir=cfg.signatures_dir)
        custom_count = max(0, len(all_sigs) - len(bundled))
        extra_note = f" (+{custom_count} custom in {cfg.signatures_dir})" if custom_count else ""
        checks.append(
            DoctorCheck(
                name="signatures",
                status="ok" if all_sigs else "warn",
                detail=f"Loaded {len(all_sigs)} passive fingerprint signatures{extra_note}",
            )
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(DoctorCheck(name="signatures", status="error", detail=str(exc)))

    nvd_key, nvd_src = cfg.get_nvd_api_key()
    has_nvd_key = bool(nvd_key)
    checks.append(
        DoctorCheck(
            name="nvd_api_key",
            status="ok",
            detail=(
                f"NVD_API_KEY set via {nvd_src} (50 req/30s quota)"
                if has_nvd_key
                else "NVD_API_KEY not set (using unauthenticated 5 req/30s quota)"
            ),
        )
    )

    ant_key, ant_source = cfg.get_anthropic_api_key()
    key_type = classify_anthropic_key(ant_key)
    if not ant_key:
        checks.append(
            DoctorCheck(
                name="anthropic_api_key",
                status="ok",
                detail="ANTHROPIC_API_KEY not set (optional; required for `s1shell ai`)",
            )
        )
    elif key_type == "admin":
        checks.append(
            DoctorCheck(
                name="anthropic_api_key",
                status="warn",
                detail=(
                    f"ANTHROPIC_API_KEY set ({mask_api_key(ant_key)} via {ant_source}) — "
                    "Admin key (sk-ant-admin*) detected; /v1/messages inference requires a "
                    "standard sk-ant-api* key"
                ),
            )
        )
    else:
        checks.append(
            DoctorCheck(
                name="anthropic_api_key",
                status="ok",
                detail=f"ANTHROPIC_API_KEY set ({mask_api_key(ant_key)} via {ant_source})",
            )
        )

    active_prov = cfg.get_ai_provider()
    checks.append(
        DoctorCheck(
            name="ai_provider",
            status="ok",
            detail=(
                f"provider={active_prov}, model={cfg.get_ai_model(active_prov)}, "
                f"endpoint={cfg.get_ai_base_url(active_prov)}"
            ),
        )
    )

    healthy = all(c.status != "error" for c in checks)
    return DoctorReport(home_dir=str(cfg.home_dir), checks=checks, healthy=healthy)
