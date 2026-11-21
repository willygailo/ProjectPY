"""Service orchestrator for offline `s1shell scan` tools with tamper-evident audit logging."""

from __future__ import annotations

import time
from pathlib import Path

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.errors import ExitCode
from s1shell.scan.config import scan_config
from s1shell.scan.models import ConfigScanResult, SBOMGenerateResult, SecretScanResult
from s1shell.scan.sbom import generate_cyclonedx_sbom
from s1shell.scan.secrets import scan_secrets


class ScanService:
    """Strictly offline local security scanning service (zero network traffic)."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.cfg = cfg
        self.audit = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)

    def secrets(
        self,
        path: Path,
        *,
        respect_gitignore: bool = True,
        git_staged: bool = False,
        git_diff: str | None = None,
    ) -> SecretScanResult:
        """Scan local files or git diffs for exposed credentials and secrets."""
        t0 = time.monotonic()
        res = scan_secrets(
            path,
            respect_gitignore=respect_gitignore,
            git_staged=git_staged,
            git_diff=git_diff,
        )
        self.audit.log(
            AuditEvent.create(
                category="intel",
                command="scan_secrets",
                target=str(path),
                outcome="success",
                exit_code=int(ExitCode.SUCCESS),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        )
        return res

    def config(self, path: Path) -> ConfigScanResult:
        """Audit Dockerfiles, K8s, GitHub Actions, Compose, NGINX, SSHd, and .env files."""
        t0 = time.monotonic()
        res = scan_config(path)
        self.audit.log(
            AuditEvent.create(
                category="intel",
                command="scan_config",
                target=str(path),
                outcome="success",
                exit_code=int(ExitCode.SUCCESS),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        )
        return res

    def sbom(
        self,
        path: Path,
        *,
        recursive: bool = True,
        include_manifests: bool = True,
    ) -> SBOMGenerateResult:
        """Generate a CycloneDX 1.5 JSON SBOM for a local project directory or manifest."""
        t0 = time.monotonic()
        res = generate_cyclonedx_sbom(
            path,
            recursive=recursive,
            include_manifests=include_manifests,
        )
        self.audit.log(
            AuditEvent.create(
                category="intel",
                command="scan_sbom",
                target=str(path),
                outcome="success",
                exit_code=int(ExitCode.SUCCESS),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        )
        return res
