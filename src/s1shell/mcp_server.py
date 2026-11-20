"""Stdlib JSON-RPC 2.0 stdio MCP server exposing strictly read-only offline/intel S1shell tools."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from s1shell import __version__
from s1shell.assess.diff import diff_assessments
from s1shell.assess.remediate import generate_remediation_from_file
from s1shell.audit import AuditLogger
from s1shell.codec.service import CodecService
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService
from s1shell.cve.models import CVESearchFilter
from s1shell.cve.service import CVEService
from s1shell.doctor import run_doctor
from s1shell.errors import S1ShellError
from s1shell.fingerprint.service import FingerprintService
from s1shell.intel.service import IntelService
from s1shell.models import dumps_json
from s1shell.scope import ScopeManager

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "s1shell_doctor",
        "description": (
            "Run local diagnostics on S1shell environment, permissions, scope, "
            "and hash-chained audit log."
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
        "name": "s1shell_fingerprint_from_profile",
        "description": (
            "Passively identify technologies/CDNs/WAFs from a saved profile.json "
            "artifact (zero network traffic)."
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
            "Search NVD CVE intelligence by keyword or CPE with optional CISA KEV/EPSS "
            "enrichment (zero target contact)."
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
            "Retrieve detailed NVD + CVE.org intelligence for a specific CVE ID "
            "(zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"},
                "offline": {"type": "boolean", "default": False},
                "enrich": {"type": "boolean", "default": False},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "s1shell_cve_audit",
        "description": (
            "Audit pinned lockfiles (requirements.txt, package-lock.json, go.mod, "
            "Cargo.lock) or CycloneDX SBOMs via OSV.dev + KEV/EPSS (zero target contact)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
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
            "from a saved assess.json artifact."
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
            "Query passive third-party threat intelligence (VirusTotal, GreyNoise, "
            "urlscan.io Search) for a domain or IP (zero target contact)."
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
            "Query GitHub Security Advisories (GHSA) by CVE ID or ecosystem+package "
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
            "Query passive Certificate Transparency logs (crt.sh) for a domain "
            "(zero target contact)."
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
            "Query public RFC 7480-7484 RDAP registration records for a domain or IP "
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
]


class S1ShellMCPServer:
    """Handles MCP JSON-RPC 2.0 requests for strictly read-only/offline S1shell operations."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        cve_service: CVEService | None = None,
        dep_audit_service: DependencyAuditService | None = None,
        intel_service: IntelService | None = None,
        fingerprint_service: FingerprintService | None = None,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.cfg = cfg
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
        self.codec_service = CodecService()

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "s1shell_doctor":
            return dumps_json(run_doctor(self.cfg))
        if name == "s1shell_scope_list":
            return dumps_json({"entries": self.scope_manager.load()})
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
        raise KeyError(f"Unknown MCP tool '{name}'.")

    def handle_request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 request object and return response (or None for notify)."""
        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params") or {}

        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "s1shell-readonly-mcp", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SPEC}}

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
