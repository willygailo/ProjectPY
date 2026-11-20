"""Online Streamable HTTP & Local Stdio JSON-RPC 2.0 MCP server for S1shell."""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

import httpx

from s1shell import __version__
from s1shell.ai.service import AIService
from s1shell.assess.diff import diff_assessments
from s1shell.assess.remediate import generate_remediation_from_file
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.codec.service import CodecService
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService
from s1shell.cve.models import CVESearchFilter
from s1shell.cve.service import CVEService
from s1shell.doctor import run_doctor
from s1shell.errors import NetworkError, S1ShellError, UnauthorizedError, ValidationError
from s1shell.fingerprint.service import FingerprintService
from s1shell.intel.service import IntelService
from s1shell.models import dumps_json
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager

MCP_PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_MCP_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8765
_MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB
SUPPORTED_MCP_CLIENTS = ("antigravity", "claude", "cursor", "vscode", "windsurf", "http")

BASE_TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "s1shell_doctor",
        "description": (
            "Run local diagnostics on S1shell environment, permissions, scope, "
            "API key status (masked), AI skills, and hash-chained audit log."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "s1shell_scope_list",
        "description": (
            "List configured authorized scope and exclusion entries from scope.yaml (offline)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "s1shell_scope_check",
        "description": (
            "Check whether a target URL, domain, or IP matches active scope.yaml allow/exclude "
            "rules and verify safe DNS resolution (never sends HTTP/TLS packets to target)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL, domain, IPv4, or IPv6 to validate against scope.",
                }
            },
            "required": ["target"],
        },
    },
    {
        "name": "s1shell_fingerprint_from_profile",
        "description": (
            "Passively identify technologies/CDNs/WAFs and EOL software from a saved "
            "profile.json artifact (zero network traffic)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile_path": {
                    "type": "string",
                    "description": "Path to saved S1shell profile JSON artifact.",
                }
            },
            "required": ["profile_path"],
        },
    },
    {
        "name": "s1shell_cve_search",
        "description": (
            "Search live NVD 2.0 CVE intelligence by keyword or CPE with optional CISA KEV/EPSS "
            "enrichment (online passive feed; zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string"},
                "cpe": {"type": "string"},
                "min_cvss": {"type": "number"},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "limit": {"type": "integer", "default": 15},
                "offline": {"type": "boolean", "default": False},
                "enrich": {"type": "boolean", "default": False},
                "kev_only": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "s1shell_cve_get",
        "description": (
            "Retrieve live NVD + CVE.org + GHSA intelligence for one or more CVE IDs "
            "(online passive feed; zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "Single CVE ID (e.g. CVE-2021-23017)."},
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Batch list of CVE IDs to look up together.",
                },
                "offline": {"type": "boolean", "default": False},
                "enrich": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "s1shell_cve_audit",
        "description": (
            "Audit pinned lockfiles (requirements.txt, uv.lock, poetry.lock, Pipfile.lock, "
            "package-lock.json, yarn.lock, pnpm-lock.yaml, go.mod, Cargo.lock, composer.lock, "
            "Gemfile.lock, pom.xml), CycloneDX/SPDX 2.3 SBOMs, or a directory recursively via "
            "live OSV.dev + CVSS v3.1 + CISA KEV/EPSS (zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "recursive": {"type": "boolean", "default": False},
                "offline": {"type": "boolean", "default": False},
                "enrich": {"type": "boolean", "default": False},
                "kev_only": {"type": "boolean", "default": False},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "s1shell_assess_diff",
        "description": (
            "Compare baseline vs current assess.json artifacts to detect security "
            "posture drift (offline)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_path": {"type": "string"},
                "current_path": {"type": "string"},
            },
            "required": ["baseline_path", "current_path"],
        },
    },
    {
        "name": "s1shell_remediate",
        "description": (
            "Generate deterministic offline defensive hardening configuration snippets "
            "(nginx/apache/caddy/express/generic + DNS + security.txt) from a saved assess.json."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "assess_path": {"type": "string"},
                "stack": {
                    "type": "string",
                    "enum": ["auto", "nginx", "apache", "caddy", "express", "generic"],
                    "default": "auto",
                },
            },
            "required": ["assess_path"],
        },
    },
    {
        "name": "s1shell_intel_lookup",
        "description": (
            "Query live passive third-party threat intelligence (VirusTotal, GreyNoise, "
            "urlscan.io Search, RDAP) for a domain or IP (zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "pinned_ip": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}},
                "offline": {"type": "boolean", "default": False},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "s1shell_intel_advisory",
        "description": (
            "Query live GitHub Security Advisories (GHSA) by CVE ID or ecosystem+package "
            "(zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"},
                "ecosystem": {"type": "string"},
                "package": {"type": "string"},
                "limit": {"type": "integer", "default": 15},
                "offline": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "s1shell_audit_list",
        "description": (
            "Read recent append-only JSONL audit log entries with optional filters (offline)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50},
                "category": {"type": "string"},
                "outcome": {"type": "string"},
                "target": {"type": "string"},
            },
        },
    },
    {
        "name": "s1shell_audit_verify",
        "description": (
            "Verify SHA-256 hash chain integrity of S1shell's tamper-evident audit.log (offline)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "s1shell_intel_ct",
        "description": (
            "Query live passive Certificate Transparency logs (crt.sh) for a domain "
            "(zero target contact, no API key required)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "offline": {"type": "boolean"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "s1shell_intel_rdap",
        "description": (
            "Query live public RFC 7480-7484 RDAP registration records for a domain or IP "
            "(zero target contact, no API key required)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "offline": {"type": "boolean"},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "s1shell_codec_decode",
        "description": (
            "Decode strings offline via auto-detect, explicit codec (base64, base64url, base32, "
            "base58, hex, url, html, unicode, binary, octal, decimal, morse, punycode, rot13, "
            "caesar, gzip, zlib, deflate, saml, jwt), or ordered chain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "encoding": {"type": "string"},
                "chain": {"type": "array", "items": {"type": "string"}},
                "shift": {"type": "integer"},
                "all_shifts": {"type": "boolean"},
                "max_depth": {"type": "integer"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "s1shell_codec_encode",
        "description": "Encode text offline using a single codec or ordered chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "encoding": {"type": "string"},
                "chain": {"type": "array", "items": {"type": "string"}},
                "shift": {"type": "integer"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "s1shell_codec_inspect",
        "description": (
            "Smart offline inspector identifying JWTs, X.509 PEM certificates, hash formats, "
            "Unix timestamps, Shannon entropy, and nested encodings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "max_depth": {"type": "integer"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "s1shell_codec_hash",
        "description": (
            "Compute offline cryptographic digests (md5, sha1, sha256, sha384, sha512, "
            "blake2b, crc32) and Shannon entropy for input text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "algos": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional subset of algorithms to compute.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "s1shell_ai_skills_list",
        "description": (
            "List S1shell's bundled and custom defensive AI security skills (`skills.yaml` + "
            "`~/.s1shell/skills.d/*.yaml`)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "s1shell_ai_prepare_context",
        "description": (
            "Prepare an offline distilled, redacted, and prompt-injection-isolated context bundle "
            "for a defensive AI skill from saved S1shell JSON artifacts (zero LLM API calls)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths to saved S1shell JSON artifacts or an assessment folder.",
                },
                "skill": {"type": "string", "description": "Optional defensive skill ID."},
                "mode": {
                    "type": "string",
                    "enum": ["triage", "executive", "remediate"],
                    "default": "triage",
                },
                "redact": {"type": "boolean", "default": True},
                "compact": {"type": "boolean", "default": True},
                "prompt": {"type": "string"},
            },
            "required": ["input_paths"],
        },
    },
    {
        "name": "s1shell_ai_analyze",
        "description": (
            "Run defensive AI analysis over saved S1shell JSON artifacts using configured online "
            "or local Ollama LLM with NDA redaction (default on), skills, pipelines, and citation "
            "grounding verification (zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths to saved S1shell JSON artifacts or an assessment folder.",
                },
                "prompt": {"type": "string"},
                "skill": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["triage", "executive", "remediate"],
                    "default": "triage",
                },
                "pipeline": {
                    "type": "string",
                    "enum": ["deep-triage", "purple-team", "executive-pack"],
                },
                "structured": {"type": "boolean", "default": False},
                "provider": {"type": "string"},
                "model": {"type": "string"},
                "redact": {"type": "boolean", "default": True},
                "restore": {"type": "boolean", "default": False},
                "compact": {"type": "boolean", "default": True},
                "local_only": {"type": "boolean", "default": False},
                "use_cache": {"type": "boolean", "default": True},
                "max_tokens": {"type": "integer", "default": 1024},
            },
        },
    },
]

SCOPED_TARGET_TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "s1shell_profile",
        "description": (
            "Run a strictly read-only guarded target profile (1 GET + TLS + DNS) against an "
            "authorized target in scope.yaml. Fail-closed on out-of-scope or excluded hosts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized URL, domain, or IP."},
                "tls_versions": {"type": "boolean", "default": False},
                "dns_security": {"type": "boolean", "default": False},
                "well_known": {"type": "boolean", "default": False},
                "check_methods": {"type": "boolean", "default": False},
            },
            "required": ["target"],
        },
    },
    {
        "name": "s1shell_fingerprint",
        "description": (
            "Passively fingerprint server/CDN/WAF/EOL technologies from 1 normal GET response "
            "against an authorized target in scope.yaml (fail-closed policy gate)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized URL, domain, or IP."},
            },
            "required": ["target"],
        },
    },
    {
        "name": "s1shell_assess",
        "description": (
            "Run S1shell's unified read-only defensive assessment (profile -> fingerprint/EOL -> "
            "optional CVE/intel -> posture score -> remediation snippets) against an authorized "
            "target in scope.yaml (fail-closed policy gate + SHA-256 audit log)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized URL, domain, or IP."},
                "preset": {"type": "string", "enum": ["web", "api", "strict"], "default": "web"},
                "enrich_cve": {"type": "boolean", "default": False},
                "intel": {"type": "boolean", "default": False},
                "well_known": {"type": "boolean", "default": False},
                "check_methods": {"type": "boolean", "default": False},
                "skip_cve": {"type": "boolean", "default": False},
                "min_cvss": {"type": "number", "default": 7.0},
                "cve_limit": {"type": "integer", "default": 10},
            },
            "required": ["target"],
        },
    },
]

# Backward-compatible default tool list alias
TOOLS_SPEC: list[dict[str, Any]] = BASE_TOOLS_SPEC

RESOURCES_SPEC: list[dict[str, Any]] = [
    {
        "uri": "s1shell://doctor",
        "name": "S1shell Environment & Diagnostics",
        "description": "Local environment health, masked API key status, signatures & AI skills.",
        "mimeType": "application/json",
    },
    {
        "uri": "s1shell://scope",
        "name": "Authorized Scope Rules (scope.yaml)",
        "description": "Active authorized targets and deny-first exclusion entries.",
        "mimeType": "application/json",
    },
    {
        "uri": "s1shell://skills",
        "name": "Defensive AI Security Skills Catalog",
        "description": "All bundled and custom (~/.s1shell/skills.d/*.yaml) defensive AI skills.",
        "mimeType": "application/json",
    },
    {
        "uri": "s1shell://audit/recent",
        "name": "Recent Hash-Chained Audit Log Events",
        "description": "Latest 50 tamper-evident SHA-256 audit log entries.",
        "mimeType": "application/json",
    },
]


def is_loopback_host(host: str) -> bool:
    """Return True if `host` refers strictly to a loopback address (`localhost`, 127/8, ::1)."""
    clean = host.strip().lower().strip("[]").rstrip(".")
    if clean == "localhost":
        return True
    try:
        return ipaddress.ip_address(clean).is_loopback
    except ValueError:
        return False


def is_origin_allowed(origin: str | None, allowed_origins: set[str]) -> bool:
    """Validate HTTP `Origin` header to defend Streamable HTTP MCP against DNS rebinding."""
    if origin is None or not origin.strip():
        return True
    cleaned = origin.strip().rstrip("/")
    if cleaned in {o.strip().rstrip("/") for o in allowed_origins}:
        return True
    parts = urlsplit(cleaned)
    host = (parts.hostname or "").strip().lower().rstrip(".")
    return bool(host and is_loopback_host(host))


def build_mcp_client_config(
    client: str,
    *,
    transport: str = "http",
    url: str = f"http://{DEFAULT_MCP_HOST}:{DEFAULT_MCP_PORT}/mcp",
    token: str | None = None,
    command: str = "s1shell",
    allow_scoped_targets: bool = False,
) -> dict[str, Any]:
    """Generate a copy-paste MCP client JSON configuration snippet."""
    norm_client = client.strip().lower()
    if norm_client not in SUPPORTED_MCP_CLIENTS:
        raise ValidationError(
            f"Unsupported MCP client '{client}'. Choose one of: {', '.join(SUPPORTED_MCP_CLIENTS)}."
        )
    norm_transport = transport.strip().lower()
    if norm_transport not in {"http", "stdio"}:
        raise ValidationError("MCP config --transport must be 'http' or 'stdio'.")

    if norm_transport == "stdio":
        args = ["mcp", "serve"]
        if allow_scoped_targets:
            args.extend(["--allow-scoped-targets", "--authorized"])
        entry: dict[str, Any] = {"command": command, "args": args}
        root_key = "servers" if norm_client == "vscode" else "mcpServers"
        if norm_client == "vscode":
            entry = {"type": "stdio", **entry}
        return {root_key: {"s1shell": entry}}

    auth_token = token.strip() if token and token.strip() else "YOUR_S1SHELL_MCP_TOKEN"
    headers = {"Authorization": f"Bearer {auth_token}"}

    if norm_client == "vscode":
        return {
            "servers": {
                "s1shell": {
                    "type": "http",
                    "url": url,
                    "headers": headers,
                }
            }
        }
    if norm_client == "windsurf":
        return {
            "mcpServers": {
                "s1shell": {
                    "serverUrl": url,
                    "headers": headers,
                }
            }
        }
    return {
        "mcpServers": {
            "s1shell": {
                "url": url,
                "headers": headers,
            }
        }
    }


def ping_mcp_http(
    url: str,
    *,
    token: str | None = None,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Probe a running online S1shell Streamable HTTP MCP server and report capabilities."""
    clean_url = url.strip()
    parts = urlsplit(clean_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValidationError(f"Invalid MCP server URL '{url}'. Expected http(s)://host:port/mcp.")

    health_url = f"{parts.scheme}://{parts.netloc}/healthz"
    headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if token and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"

    started = time.monotonic()
    use_env_proxy = not is_loopback_host(parts.hostname or "")
    try:
        with httpx.Client(
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
            trust_env=use_env_proxy,
        ) as client:
            health_resp = client.get(health_url)
            health_data = health_resp.json() if health_resp.status_code == 200 else {}

            init_resp = client.post(
                clean_url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "clientInfo": {"name": "s1shell-mcp-ping", "version": __version__},
                    },
                },
            )
            if init_resp.status_code == 401:
                raise NetworkError(
                    "MCP server rejected authentication (HTTP 401). "
                    "Pass --token or set S1SHELL_MCP_TOKEN."
                )
            if init_resp.status_code == 403:
                raise NetworkError("MCP server rejected request origin (HTTP 403).")
            if init_resp.status_code >= 400:
                raise NetworkError(f"MCP initialize failed with HTTP {init_resp.status_code}.")
            init_json = init_resp.json()
            init_res = init_json.get("result") if isinstance(init_json, dict) else {}
            if not isinstance(init_res, dict):
                raise NetworkError("MCP initialize returned an unexpected JSON-RPC payload.")

            tools_resp = client.post(
                clean_url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            tools_list = (tools_resp.json().get("result") or {}).get("tools", [])

            res_resp = client.post(
                clean_url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
            )
            resources_list = (res_resp.json().get("result") or {}).get("resources", [])

            prm_resp = client.post(
                clean_url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
            )
            prompts_list = (prm_resp.json().get("result") or {}).get("prompts", [])
    except httpx.HTTPError as exc:
        raise NetworkError(f"Failed to reach online MCP server '{clean_url}': {exc}") from exc
    except ValueError as exc:
        raise NetworkError(f"Invalid JSON response from MCP server '{clean_url}': {exc}") from exc

    latency_ms = int((time.monotonic() - started) * 1000)
    raw_srv_info = init_res.get("serverInfo")
    srv_info: dict[str, Any] = raw_srv_info if isinstance(raw_srv_info, dict) else {}
    return {
        "artifact_type": "mcp_ping_report",
        "healthy": True,
        "url": clean_url,
        "health_endpoint_ok": health_resp.status_code == 200,
        "server_name": str(srv_info.get("name", "s1shell-mcp")),
        "server_version": str(srv_info.get("version", __version__)),
        "protocol_version": str(init_res.get("protocolVersion", MCP_PROTOCOL_VERSION)),
        "tools_count": len(tools_list) if isinstance(tools_list, list) else 0,
        "resources_count": len(resources_list) if isinstance(resources_list, list) else 0,
        "prompts_count": len(prompts_list) if isinstance(prompts_list, list) else 0,
        "scoped_targets_enabled": bool(health_data.get("scoped_targets_enabled", False)),
        "auth_used": bool(token and token.strip()),
        "latency_ms": latency_ms,
    }


class S1ShellMCPServer:
    """Handles MCP JSON-RPC 2.0 tools, resources, and prompts over stdio or Streamable HTTP."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        cve_service: CVEService | None = None,
        dep_audit_service: DependencyAuditService | None = None,
        intel_service: IntelService | None = None,
        fingerprint_service: FingerprintService | None = None,
        profile_service: ProfileService | None = None,
        assess_service: AssessService | None = None,
        ai_service: AIService | None = None,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        allow_scoped_targets: bool = False,
        authorized: bool = False,
    ) -> None:
        if allow_scoped_targets and not authorized:
            raise UnauthorizedError(
                "--allow-scoped-targets requires explicit --authorized confirmation on MCP "
                "server startup (fail-closed policy gate)."
            )
        self.cfg = cfg
        self.allow_scoped_targets = allow_scoped_targets
        self.authorized = authorized
        self.scope_manager = (
            scope_manager if scope_manager is not None else ScopeManager(cfg.scope_file)
        )
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self.cve_service = (
            cve_service
            if cve_service is not None
            else CVEService(cfg, audit_logger=self.audit_logger)
        )
        self.dep_audit_service = (
            dep_audit_service
            if dep_audit_service is not None
            else DependencyAuditService(cfg, audit_logger=self.audit_logger)
        )
        self.intel_service = (
            intel_service
            if intel_service is not None
            else IntelService(cfg, audit_logger=self.audit_logger)
        )
        self.fingerprint_service = (
            fingerprint_service
            if fingerprint_service is not None
            else FingerprintService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
            )
        )
        self.profile_service = (
            profile_service
            if profile_service is not None
            else ProfileService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
            )
        )
        self.ai_service = (
            ai_service if ai_service is not None else AIService(cfg, audit_logger=self.audit_logger)
        )
        self.assess_service = (
            assess_service
            if assess_service is not None
            else AssessService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
                profile_service=self.profile_service,
                fingerprint_service=self.fingerprint_service,
                cve_service=self.cve_service,
                intel_service=self.intel_service,
                ai_service=self.ai_service,
            )
        )
        self.codec_service = CodecService()

    @property
    def active_tools_spec(self) -> list[dict[str, Any]]:
        """Return currently enabled MCP tool schemas."""
        if self.allow_scoped_targets:
            return [*BASE_TOOLS_SPEC, *SCOPED_TARGET_TOOLS_SPEC]
        return list(BASE_TOOLS_SPEC)

    def _list_prompts(self) -> list[dict[str, Any]]:
        catalog = self.ai_service.list_skills()
        prompts: list[dict[str, Any]] = []
        for sk in catalog.skills:
            prompts.append(
                {
                    "name": sk.id,
                    "description": f"[{sk.category}] {sk.description}",
                    "arguments": [
                        {
                            "name": "input_path",
                            "description": "Optional path to saved S1shell JSON artifact.",
                            "required": False,
                        },
                        {
                            "name": "focus",
                            "description": "Optional operator question or focus area.",
                            "required": False,
                        },
                    ],
                }
            )
        return prompts

    def _get_prompt(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        skill = self.ai_service.get_skill(name)
        focus = str(arguments.get("focus") or "").strip() or None
        raw_input = str(arguments.get("input_path") or "").strip()
        if raw_input:
            bundle = self.ai_service.prepare_context(
                inputs=[Path(raw_input)],
                skill=skill.id,
                redact=True,
                compact=True,
                prompt=focus,
            )
            text = f"{bundle['system_prompt']}\n\n---\n\n{bundle['user_prompt']}"
        else:
            task = focus or skill.user_template or skill.description
            text = f"{skill.system_prompt}\n\nOperator request:\n{task}"
        return {
            "description": skill.description,
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": text},
                }
            ],
        }

    def _read_resource(self, uri: str) -> dict[str, Any]:
        clean = uri.strip()
        if clean == "s1shell://doctor":
            text = dumps_json(run_doctor(self.cfg))
        elif clean == "s1shell://scope":
            text = dumps_json({"entries": self.scope_manager.load()})
        elif clean == "s1shell://skills":
            text = dumps_json(self.ai_service.list_skills())
        elif clean == "s1shell://audit/recent":
            text = dumps_json({"events": self.audit_logger.read_recent(limit=50)})
        else:
            raise KeyError(f"Unknown MCP resource URI '{uri}'.")
        return {
            "contents": [
                {
                    "uri": clean,
                    "mimeType": "application/json",
                    "text": text,
                }
            ]
        }

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "s1shell_doctor":
            return dumps_json(run_doctor(self.cfg))
        if name == "s1shell_scope_list":
            return dumps_json({"entries": self.scope_manager.load()})
        if name == "s1shell_scope_check":
            target = str(arguments.get("target", ""))
            return dumps_json(self.scope_manager.check_target(target))
        if name == "s1shell_fingerprint_from_profile":
            path = Path(str(arguments.get("profile_path", "")))
            return dumps_json(self.fingerprint_service.from_profile(path))
        if name == "s1shell_cve_search":
            flt = CVESearchFilter(
                keyword=arguments.get("keyword"),
                cpe=arguments.get("cpe"),
                min_cvss=(
                    float(arguments["min_cvss"]) if arguments.get("min_cvss") is not None else None
                ),
                severity=arguments.get("severity"),
                limit=int(arguments.get("limit", 15)),
                kev_only=bool(arguments.get("kev_only", False)),
            )
            res = self.cve_service.search(
                flt,
                offline=bool(arguments.get("offline", False)),
                enrich=bool(arguments.get("enrich", False)),
            )
            return dumps_json(res)
        if name == "s1shell_cve_get":
            raw_ids = arguments.get("cve_ids")
            if isinstance(raw_ids, list) and raw_ids:
                res = self.cve_service.get_many(
                    [str(cid) for cid in raw_ids],
                    offline=bool(arguments.get("offline", False)),
                    enrich=bool(arguments.get("enrich", False)),
                )
            else:
                cve_id = str(arguments.get("cve_id", ""))
                res = self.cve_service.get(
                    cve_id,
                    offline=bool(arguments.get("offline", False)),
                    enrich=bool(arguments.get("enrich", False)),
                )
            return dumps_json(res)
        if name == "s1shell_cve_audit":
            fpath = Path(str(arguments.get("file_path", "")))
            dep_res = self.dep_audit_service.audit_path(
                fpath,
                recursive=bool(arguments.get("recursive", False)),
                offline=bool(arguments.get("offline", False)),
                enrich=bool(arguments.get("enrich", False)),
                kev_only=bool(arguments.get("kev_only", False)),
            )
            return dumps_json(dep_res)
        if name == "s1shell_assess_diff":
            base = Path(str(arguments.get("baseline_path", "")))
            curr = Path(str(arguments.get("current_path", "")))
            return dumps_json(diff_assessments(base, curr))
        if name == "s1shell_remediate":
            assess_path = Path(str(arguments.get("assess_path", "")))
            stack = str(arguments.get("stack") or "auto")
            return dumps_json(generate_remediation_from_file(assess_path, stack=stack))
        if name == "s1shell_intel_lookup":
            raw_sources = arguments.get("sources")
            src_list = [str(s) for s in raw_sources] if isinstance(raw_sources, list) else None
            intel_res = self.intel_service.lookup(
                str(arguments.get("indicator", "")),
                pinned_ip=arguments.get("pinned_ip"),
                sources=src_list,
                offline=bool(arguments.get("offline", False)),
            )
            return dumps_json(intel_res)
        if name == "s1shell_intel_advisory":
            adv_res = self.intel_service.advisories(
                cve_id=arguments.get("cve_id"),
                ecosystem=arguments.get("ecosystem"),
                package=arguments.get("package"),
                limit=int(arguments.get("limit", 15)),
                offline=bool(arguments.get("offline", False)),
            )
            return dumps_json(adv_res)
        if name == "s1shell_intel_ct":
            ct_res = self.intel_service.ct_lookup(
                str(arguments.get("domain", "")),
                offline=bool(arguments.get("offline", False)),
            )
            return dumps_json(ct_res)
        if name == "s1shell_intel_rdap":
            rdap_res = self.intel_service.rdap_lookup(
                str(arguments.get("indicator", "")),
                offline=bool(arguments.get("offline", False)),
            )
            return dumps_json(rdap_res)
        if name == "s1shell_codec_decode":
            raw_chain = arguments.get("chain")
            chain_list = [str(c) for c in raw_chain] if isinstance(raw_chain, list) else None
            dec_res = self.codec_service.decode(
                str(arguments.get("text", "")).encode("utf-8"),
                encoding=str(arguments.get("encoding") or "auto"),
                chain=chain_list,
                shift=int(arguments.get("shift", 13)),
                all_shifts=bool(arguments.get("all_shifts", False)),
                max_depth=int(arguments.get("max_depth", 6)),
            )
            return dumps_json(dec_res)
        if name == "s1shell_codec_encode":
            raw_chain = arguments.get("chain")
            chain_list = [str(c) for c in raw_chain] if isinstance(raw_chain, list) else None
            enc_res = self.codec_service.encode(
                str(arguments.get("text", "")).encode("utf-8"),
                encoding=arguments.get("encoding"),
                chain=chain_list,
                shift=int(arguments.get("shift", 13)),
            )
            return dumps_json(enc_res)
        if name == "s1shell_codec_inspect":
            ins_res = self.codec_service.inspect(
                str(arguments.get("text", "")).encode("utf-8"),
                max_depth=int(arguments.get("max_depth", 6)),
            )
            return dumps_json(ins_res)
        if name == "s1shell_codec_hash":
            raw_algos = arguments.get("algos")
            algos_list = [str(a) for a in raw_algos] if isinstance(raw_algos, list) else None
            hash_res = self.codec_service.hash_data(
                str(arguments.get("text", "")).encode("utf-8"),
                source="mcp",
                algos=algos_list,
            )
            return dumps_json(hash_res)
        if name == "s1shell_ai_skills_list":
            return dumps_json(self.ai_service.list_skills())
        if name == "s1shell_ai_prepare_context":
            raw_paths = arguments.get("input_paths")
            paths = [Path(str(p)) for p in raw_paths] if isinstance(raw_paths, list) else []
            prep = self.ai_service.prepare_context(
                inputs=paths,
                skill=arguments.get("skill"),
                mode=str(arguments.get("mode") or "triage"),
                redact=bool(arguments.get("redact", True)),
                compact=bool(arguments.get("compact", True)),
                prompt=arguments.get("prompt"),
            )
            return dumps_json(prep)
        if name == "s1shell_ai_analyze":
            raw_paths = arguments.get("input_paths")
            paths = [Path(str(p)) for p in raw_paths] if isinstance(raw_paths, list) else []
            ai_res = self.ai_service.analyze(
                inputs=paths,
                prompt=arguments.get("prompt"),
                skill=arguments.get("skill"),
                mode=str(arguments.get("mode") or "triage"),
                pipeline=arguments.get("pipeline"),
                structured=bool(arguments.get("structured", False)),
                provider=arguments.get("provider"),
                model=arguments.get("model"),
                redact=bool(arguments.get("redact", True)),
                restore=bool(arguments.get("restore", False)),
                compact=bool(arguments.get("compact", True)),
                local_only=bool(arguments.get("local_only", False)),
                use_cache=bool(arguments.get("use_cache", True)),
                max_tokens=int(arguments.get("max_tokens", 1024)),
            )
            return dumps_json(ai_res)
        if name == "s1shell_audit_list":
            events = self.audit_logger.read_recent(
                limit=int(arguments.get("limit", 50)),
                category=arguments.get("category"),
                outcome=arguments.get("outcome"),
                target=arguments.get("target"),
            )
            return dumps_json({"events": events})
        if name == "s1shell_audit_verify":
            return dumps_json(self.audit_logger.verify())

        # Opt-in fail-closed guarded scoped target tools
        if name in {"s1shell_profile", "s1shell_fingerprint", "s1shell_assess"}:
            if not self.allow_scoped_targets:
                raise UnauthorizedError(
                    f"Tool '{name}' is disabled. Start MCP server with "
                    "`--allow-scoped-targets --authorized` to enable fail-closed target tools."
                )
            target = str(arguments.get("target", ""))
            if name == "s1shell_profile":
                prof_res = self.profile_service.profile(
                    target,
                    authorized=True,
                    check_tls_versions=bool(arguments.get("tls_versions", False)),
                    check_dns_security=bool(arguments.get("dns_security", False)),
                    check_well_known=bool(arguments.get("well_known", False)),
                    check_methods=bool(arguments.get("check_methods", False)),
                )
                return dumps_json(prof_res)
            if name == "s1shell_fingerprint":
                fp_res = self.fingerprint_service.inspect_target(target, authorized=True)
                return dumps_json(fp_res)
            assess_res = self.assess_service.assess(
                target,
                authorized=True,
                preset=str(arguments.get("preset") or "web"),
                enrich_cve=bool(arguments.get("enrich_cve", False)),
                run_intel=bool(arguments.get("intel", False)),
                check_well_known=bool(arguments.get("well_known", False)),
                check_methods=bool(arguments.get("check_methods", False)),
                skip_cve=bool(arguments.get("skip_cve", False)),
                min_cvss=float(arguments.get("min_cvss", 7.0)),
                cve_limit=int(arguments.get("cve_limit", 10)),
            )
            return dumps_json(assess_res)

        raise KeyError(f"Unknown MCP tool '{name}'.")

    def handle_request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 request object and return response (or None for notify)."""
        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params") or {}

        if method == "notifications/initialized":
            return None

        if method == "initialize":
            req_proto = str(params.get("protocolVersion") or "")
            proto = (
                req_proto if req_proto in SUPPORTED_MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": proto,
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                    },
                    "serverInfo": {"name": "s1shell-mcp", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.active_tools_spec},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                args = {}
            try:
                text = self._call_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text}],
                        "isError": False,
                    },
                }
            except KeyError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": str(exc)},
                }
            except (S1ShellError, ValueError, OSError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {exc}"}],
                        "isError": True,
                    },
                }

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": RESOURCES_SPEC},
            }

        if method == "resources/read":
            uri = str(params.get("uri", ""))
            try:
                res_payload = self._read_resource(uri)
                return {"jsonrpc": "2.0", "id": req_id, "result": res_payload}
            except KeyError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(exc)},
                }
            except (S1ShellError, ValueError, OSError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(exc)},
                }

        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"prompts": self._list_prompts()},
            }

        if method == "prompts/get":
            prompt_name = str(params.get("name", ""))
            p_args = params.get("arguments") or {}
            if not isinstance(p_args, dict):
                p_args = {}
            try:
                prompt_payload = self._get_prompt(prompt_name, p_args)
                return {"jsonrpc": "2.0", "id": req_id, "result": prompt_payload}
            except (S1ShellError, ValueError, KeyError, OSError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(exc)},
                }

        if req_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(
        self,
        *,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> int:
        """Run line-delimited JSON-RPC 2.0 loop over stdin/stdout until EOF."""
        in_stream = stdin if stdin is not None else sys.stdin
        out_stream = stdout if stdout is not None else sys.stdout
        for raw_line in in_stream:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                continue
            if not isinstance(msg, dict):
                continue
            resp = self.handle_request(msg)
            if resp is not None:
                out_stream.write(json.dumps(resp) + "\n")
                out_stream.flush()
        return 0

    def create_http_server(
        self,
        *,
        host: str = DEFAULT_MCP_HOST,
        port: int = DEFAULT_MCP_PORT,
        auth_token: str | None = None,
        allowed_origins: list[str] | None = None,
    ) -> ThreadingHTTPServer:
        """Build a hardened stdlib Streamable HTTP MCP server (`POST /mcp`, `GET /healthz`)."""
        clean_host = host.strip() or DEFAULT_MCP_HOST
        clean_token = auth_token.strip() if auth_token and auth_token.strip() else None
        if not is_loopback_host(clean_host) and clean_token is None:
            raise ValidationError(
                f"Binding online MCP HTTP server to non-loopback host '{clean_host}' requires "
                "--token, --generate-token, or S1SHELL_MCP_TOKEN."
            )
        if port < 0 or port > 65535:
            raise ValidationError(f"Invalid --port {port}; expected 0..65535.")

        origin_allowlist = set(allowed_origins or [])
        mcp_srv = self
        active_sessions: set[str] = set()

        class _MCPHTTPHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_json(
                self,
                status: int,
                payload: Any,
                *,
                extra_headers: dict[str, str] | None = None,
            ) -> None:
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if int(status) >= 400:
                    self.close_connection = True
                    self.send_header("Connection", "close")
                origin = self.headers.get("Origin")
                if origin and is_origin_allowed(origin, origin_allowlist):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                if extra_headers:
                    for hk, hv in extra_headers.items():
                        self.send_header(hk, hv)
                self.end_headers()
                self.wfile.write(body)

            def _check_origin(self) -> bool:
                origin = self.headers.get("Origin")
                if not is_origin_allowed(origin, origin_allowlist):
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {
                            "error": "Forbidden Origin header (DNS-rebinding protection). "
                            "Allow explicitly with --allow-origin."
                        },
                    )
                    return False
                return True

            def _check_auth(self) -> bool:
                if clean_token is None:
                    return True
                auth_hdr = (self.headers.get("Authorization") or "").strip()
                prefix = "Bearer "
                if not auth_hdr.startswith(prefix):
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {"error": "Missing or invalid Bearer Authorization header."},
                        extra_headers={"WWW-Authenticate": 'Bearer realm="s1shell-mcp"'},
                    )
                    return False
                supplied = auth_hdr[len(prefix) :].strip()
                if not secrets.compare_digest(supplied, clean_token):
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {"error": "Invalid MCP Bearer token."},
                        extra_headers={"WWW-Authenticate": 'Bearer realm="s1shell-mcp"'},
                    )
                    return False
                return True

            def do_OPTIONS(self) -> None:
                if not self._check_origin():
                    return
                self.send_response(HTTPStatus.NO_CONTENT)
                origin = self.headers.get("Origin")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, Accept, Mcp-Session-Id, MCP-Protocol-Version",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                if path == "/healthz":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "server": "s1shell-mcp",
                            "version": __version__,
                            "protocol_version": MCP_PROTOCOL_VERSION,
                            "transport": "streamable-http",
                            "tools_count": len(mcp_srv.active_tools_spec),
                            "resources_count": len(RESOURCES_SPEC),
                            "prompts_count": len(mcp_srv._list_prompts()),
                            "auth_required": clean_token is not None,
                            "scoped_targets_enabled": mcp_srv.allow_scoped_targets,
                        },
                    )
                    return
                self._send_json(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "Use POST /mcp for JSON-RPC 2.0 or GET /healthz for status."},
                )

            def do_DELETE(self) -> None:
                if not self._check_origin() or not self._check_auth():
                    return
                sid = (self.headers.get("Mcp-Session-Id") or "").strip()
                if sid:
                    active_sessions.discard(sid)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                path = urlsplit(self.path).path
                if path not in {"/mcp", "/"}:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
                    return
                if not self._check_origin() or not self._check_auth():
                    return

                raw_len = self.headers.get("Content-Length") or "0"
                try:
                    content_length = int(raw_len)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length."})
                    return
                if content_length < 0 or content_length > _MAX_HTTP_BODY_BYTES:
                    self._send_json(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        {"error": f"Payload exceeds {_MAX_HTTP_BODY_BYTES} byte limit."},
                    )
                    return

                raw_body = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32700, "message": f"Parse error: {exc}"},
                        },
                    )
                    return

                session_id = (self.headers.get("Mcp-Session-Id") or "").strip()
                if not session_id:
                    session_id = secrets.token_hex(16)
                    active_sessions.add(session_id)
                extra_hdrs = {
                    "Mcp-Session-Id": session_id,
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                }

                if isinstance(payload, list):
                    if not payload:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {"code": -32600, "message": "Empty JSON-RPC batch."},
                            },
                            extra_headers=extra_hdrs,
                        )
                        return
                    responses: list[dict[str, Any]] = []
                    for item in payload:
                        if not isinstance(item, dict):
                            responses.append(
                                {
                                    "jsonrpc": "2.0",
                                    "id": None,
                                    "error": {"code": -32600, "message": "Invalid request item."},
                                }
                            )
                            continue
                        resp = mcp_srv.handle_request(item)
                        if resp is not None:
                            responses.append(resp)
                    if not responses:
                        self.send_response(HTTPStatus.ACCEPTED)
                        for hk, hv in extra_hdrs.items():
                            self.send_header(hk, hv)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self._send_json(HTTPStatus.OK, responses, extra_headers=extra_hdrs)
                    return

                if not isinstance(payload, dict):
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32600, "message": "Invalid Request object."},
                        },
                        extra_headers=extra_hdrs,
                    )
                    return

                resp = mcp_srv.handle_request(payload)
                if resp is None:
                    self.send_response(HTTPStatus.ACCEPTED)
                    for hk, hv in extra_hdrs.items():
                        self.send_header(hk, hv)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send_json(HTTPStatus.OK, resp, extra_headers=extra_hdrs)

        ThreadingHTTPServer.allow_reuse_address = True
        return ThreadingHTTPServer((clean_host, port), _MCPHTTPHandler)

    def serve_http(
        self,
        *,
        host: str = DEFAULT_MCP_HOST,
        port: int = DEFAULT_MCP_PORT,
        auth_token: str | None = None,
        generate_token: bool = False,
        allowed_origins: list[str] | None = None,
        stderr: TextIO | None = None,
    ) -> int:
        """Start the online Streamable HTTP MCP server until interrupted."""
        err = stderr if stderr is not None else sys.stderr
        resolved_token = (
            auth_token.strip()
            if auth_token and auth_token.strip()
            else os.environ.get("S1SHELL_MCP_TOKEN", "").strip() or None
        )
        generated = False
        if generate_token and resolved_token is None:
            resolved_token = secrets.token_urlsafe(32)
            generated = True

        httpd = self.create_http_server(
            host=host,
            port=port,
            auth_token=resolved_token,
            allowed_origins=allowed_origins,
        )
        bound_host_raw, bound_port = httpd.server_address[:2]
        bound_host = (
            bound_host_raw.decode("utf-8", errors="replace")
            if isinstance(bound_host_raw, bytes)
            else str(bound_host_raw)
        )
        endpoint = f"http://{bound_host}:{bound_port}/mcp"
        health_url = f"http://{bound_host}:{bound_port}/healthz"
        mode_desc = (
            f"ONLINE + SCOPED TARGETS ({len(self.active_tools_spec)} tools)"
            if self.allow_scoped_targets
            else f"ONLINE PASSIVE INTEL & OFFLINE ({len(self.active_tools_spec)} tools)"
        )
        err.write(f"S1shell MCP Streamable HTTP server listening on {endpoint}\n")
        err.write(f"  Health : {health_url}\n")
        err.write(f"  Mode   : {mode_desc}\n")
        err.write(
            f"  Auth   : {'Bearer token REQUIRED' if resolved_token else 'None (loopback only)'}\n"
        )
        if generated and resolved_token:
            err.write(f"  Token  : {resolved_token}\n")
        err.write("Press Ctrl+C to stop.\n")
        err.flush()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0
