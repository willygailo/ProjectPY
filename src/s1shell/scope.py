"""Scope management, target normalization, and DNS anti-escape verification."""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from s1shell.config import DEFAULT_TOR_DOH_URL, DEFAULT_TOR_SOCKS_URL, atomic_write_private
from s1shell.errors import OutOfScopeError, ValidationError
from s1shell.models import utc_now, utc_now_iso
from s1shell.tor import TorDoHResolver, is_onion_host, is_v3_onion_host

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
ResolverFn = Callable[[str], list[str]]

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALLOWED_SCHEMES = {"http", "https"}
_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")
_NAT64_WELL_KNOWN_NET = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_NET = ipaddress.IPv6Network("64:ff9b:1::/48")


@dataclass(frozen=True)
class ParsedTarget:
    """Normalized representation of a user-supplied URL, domain, or IP."""

    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str
    query: str
    is_ip: bool
    ip_obj: IPAddr | None

    def effective_scheme(self, default_scheme: str = "https") -> str:
        """Return explicit scheme or fallback default scheme."""
        return self.scheme if self.scheme is not None else default_scheme

    def effective_port(self, default_scheme: str = "https") -> int:
        """Return explicit port or standard default port for scheme."""
        if self.port is not None:
            return self.port
        return 80 if self.effective_scheme(default_scheme) == "http" else 443

    def to_url(self, default_scheme: str = "https") -> str:
        """Render canonical URL string suitable for HTTP clients."""
        scheme = self.effective_scheme(default_scheme)
        is_v6 = self.is_ip and self.ip_obj and self.ip_obj.version == 6
        host_fmt = f"[{self.host}]" if is_v6 else self.host
        default_port = 80 if scheme == "http" else 443
        port = self.effective_port(default_scheme)
        port_part = f":{port}" if port != default_port else ""
        path_part = self.path if self.path else "/"
        query_part = f"?{self.query}" if self.query else ""
        return f"{scheme}://{host_fmt}{port_part}{path_part}{query_part}"


@dataclass(frozen=True)
class ScopeEntry:
    """Single authorized scope record persisted in scope.yaml."""

    id: str
    target: str
    type: str  # domain | ip | cidr | url_prefix
    include_subdomains: bool
    owner: str
    auth_ref: str
    created_at: str
    expires_at: str
    notes: str | None = None
    exclude: bool = False

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if this entry has passed its UTC expiration timestamp."""
        current = now if now is not None else utc_now()
        exp = parse_expiry(self.expires_at)
        return current > exp

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry for YAML persistence."""
        data: dict[str, Any] = {
            "id": self.id,
            "target": self.target,
            "type": self.type,
            "include_subdomains": self.include_subdomains,
            "owner": self.owner,
            "auth_ref": self.auth_ref,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if self.notes:
            data["notes"] = self.notes
        if self.exclude:
            data["exclude"] = True
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ScopeEntry:
        """Deserialize and validate a scope entry mapping."""
        required = ("id", "target", "type", "owner", "auth_ref", "created_at", "expires_at")
        for key in required:
            if key not in raw or not str(raw[key]).strip():
                raise ValidationError(f"Malformed scope entry: missing '{key}'.")
        entry_type = str(raw["type"]).strip()
        if entry_type not in {"domain", "ip", "cidr", "url_prefix", "onion"}:
            raise ValidationError(f"Malformed scope entry type: '{entry_type}'.")
        return cls(
            id=str(raw["id"]).strip(),
            target=str(raw["target"]).strip(),
            type=entry_type,
            include_subdomains=bool(raw.get("include_subdomains", False)),
            owner=str(raw["owner"]).strip(),
            auth_ref=str(raw["auth_ref"]).strip(),
            created_at=str(raw["created_at"]).strip(),
            expires_at=str(raw["expires_at"]).strip(),
            notes=str(raw["notes"]).strip() if raw.get("notes") else None,
            exclude=bool(raw.get("exclude", False)),
        )


@dataclass(frozen=True)
class ScopeCheckResult:
    """Outcome of evaluating a target against active scope entries and DNS."""

    in_scope: bool
    parsed_target: ParsedTarget
    matched_entry: ScopeEntry | None
    resolved_ips: list[str]
    pinned_ip: str | None
    reason: str


@dataclass(frozen=True)
class ScopeImportResult:
    """Summary of bulk-importing authorized targets or exclusions into scope.yaml."""

    source: str
    dry_run: bool
    added: list[ScopeEntry]
    skipped: list[str]
    errors: list[str]


def parse_expiry(value: str) -> datetime:
    """Parse YYYY-MM-DD (inclusive end of UTC day) or ISO-8601 timestamp."""
    text = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        try:
            d = datetime.strptime(text, "%Y-%m-%d").date()
        except ValueError as exc:
            raise ValidationError(f"Invalid expiry date '{value}': {exc}") from exc
        return datetime.combine(d, time(23, 59, 59), tzinfo=timezone.utc)

    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(iso_text)
    except ValueError as exc:
        raise ValidationError(
            f"Invalid expiry format '{value}'. Use YYYY-MM-DD or ISO-8601 UTC."
        ) from exc
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_hostname(host: str) -> str:
    """Validate and convert hostname to lowercase ASCII IDNA punycode."""
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned or len(cleaned) > 253 or "%" in cleaned or "*" in cleaned:
        raise ValidationError(f"Invalid hostname: '{host}'.")
    try:
        ascii_host = cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError(f"Invalid IDN hostname '{host}': {exc}") from exc
    labels = ascii_host.split(".")
    if any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
        raise ValidationError(f"Invalid hostname '{host}'.")
    return ascii_host


def _try_parse_ip(value: str) -> IPAddr | None:
    """Try parsing a bare or bracketed IP address without zone IDs."""
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def parse_target(raw_target: str) -> ParsedTarget:
    """Parse a URL, domain, IPv4, or IPv6 target into normalized fields."""
    text = raw_target.strip()
    if not text or any(ch.isspace() or ord(ch) < 32 for ch in text):
        raise ValidationError("Target cannot be empty or contain whitespace/control characters.")

    direct_ip = _try_parse_ip(text)
    if direct_ip is not None:
        return ParsedTarget(
            raw=raw_target,
            scheme=None,
            host=str(direct_ip),
            port=None,
            path="",
            query="",
            is_ip=True,
            ip_obj=direct_ip,
        )

    has_scheme = "://" in text
    if ":" in text and not has_scheme:
        # Reject unknown explicit schemes like javascript:, file:, ftp:
        prefix = text.split(":", 1)[0].lower()
        if prefix in {"javascript", "data", "file", "ftp", "ssh", "mailto"}:
            raise ValidationError(f"Unsupported scheme '{prefix}' in target '{raw_target}'.")

    probe_url = text if has_scheme else f"https://{text}"
    parts = urlsplit(probe_url)
    scheme: str | None = parts.scheme.lower() if has_scheme else None

    if scheme is not None and scheme not in _ALLOWED_SCHEMES:
        raise ValidationError(
            f"Unsupported URL scheme '{scheme}'. Only http and https are allowed."
        )
    if parts.username is not None or parts.password is not None:
        raise ValidationError("Targets must not contain embedded userinfo credentials.")
    if not parts.hostname:
        raise ValidationError(f"Could not extract host from target '{raw_target}'.")
    if "%" in (parts.netloc or ""):
        raise ValidationError("IPv6 zone identifiers are not permitted in targets.")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"Invalid port in target '{raw_target}': {exc}") from exc

    ip_obj = _try_parse_ip(parts.hostname)
    if ip_obj is not None:
        host = str(ip_obj)
        is_ip = True
    else:
        host = normalize_hostname(parts.hostname)
        if is_onion_host(host) and not is_v3_onion_host(host):
            raise ValidationError(
                f"Unsupported .onion address '{host}': only 56-character Tor v3 .onion hosts "
                "are permitted (deprecated v2 .onion addresses are rejected)."
            )
        is_ip = False

    return ParsedTarget(
        raw=raw_target,
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        is_ip=is_ip,
        ip_obj=ip_obj,
    )


def parse_scope_spec(raw_spec: str, *, include_subdomains: bool = False) -> tuple[str, str, bool]:
    """Normalize a scope target specification into (type, canonical_target, include_subdomains)."""
    text = raw_spec.strip()
    if not text or any(ch.isspace() or ord(ch) < 32 for ch in text):
        raise ValidationError("Scope target cannot be empty or contain whitespace.")

    direct_ip = _try_parse_ip(text)
    if direct_ip is not None:
        return "ip", str(direct_ip), False

    if "://" not in text and "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
            return "cidr", str(net), False
        except ValueError as exc:
            raise ValidationError(f"Invalid CIDR specification '{raw_spec}': {exc}") from exc

    if "://" in text:
        parsed = parse_target(text)
        if parsed.query:
            raise ValidationError("URL prefix scope entries must not include query strings.")
        scheme = parsed.effective_scheme()
        default_port = 80 if scheme == "http" else 443
        port = parsed.effective_port()
        host_fmt = (
            f"[{parsed.host}]"
            if parsed.is_ip and parsed.ip_obj and parsed.ip_obj.version == 6
            else parsed.host
        )
        port_part = f":{port}" if port != default_port else ""
        norm_path = parsed.path if parsed.path else "/"
        if norm_path != "/" and norm_path.endswith("/"):
            norm_path = norm_path.rstrip("/")
        return "url_prefix", f"{scheme}://{host_fmt}{port_part}{norm_path}", include_subdomains

    if text.startswith("*."):
        host = normalize_hostname(text[2:])
        if is_onion_host(host):
            if not is_v3_onion_host(host):
                raise ValidationError(
                    f"Unsupported .onion address '{host}': only 56-char Tor v3 .onion hosts "
                    "are permitted."
                )
            return "onion", host, True
        return "domain", host, True

    host = normalize_hostname(text)
    if is_onion_host(host):
        if not is_v3_onion_host(host):
            raise ValidationError(
                f"Unsupported .onion address '{host}': only 56-char Tor v3 .onion hosts "
                "are permitted."
            )
        return "onion", host, include_subdomains
    return "domain", host, include_subdomains


def _unwrap_embedded_ipv4(ip_obj: IPAddr) -> ipaddress.IPv4Address | None:
    """Extract an embedded IPv4 address from IPv4-mapped, NAT64, 6to4, or Teredo IPv6 literals."""
    if not isinstance(ip_obj, ipaddress.IPv6Address):
        return None
    if ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    if ip_obj in _NAT64_WELL_KNOWN_NET or ip_obj in _NAT64_LOCAL_NET:
        return ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
    if ip_obj.sixtofour is not None:
        return ip_obj.sixtofour
    if ip_obj.teredo is not None:
        return ip_obj.teredo[1]
    return None


def is_special_ip(ip_obj: IPAddr) -> bool:
    """Return True if an IP is non-global, private, loopback, link-local, CGNAT, or NAT64."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        embedded = _unwrap_embedded_ipv4(ip_obj)
        if embedded is not None and is_special_ip(embedded):
            return True
        if ip_obj in _NAT64_WELL_KNOWN_NET or ip_obj in _NAT64_LOCAL_NET:
            return True
    elif ip_obj in _CGNAT_NET:
        return True
    return (
        not ip_obj.is_global
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def default_dns_resolver(host: str) -> list[str]:
    """Resolve A and AAAA addresses for a hostname using stdlib getaddrinfo."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OutOfScopeError(f"DNS resolution failed for '{host}'; failing closed: {exc}") from exc

    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        raw_ip = str(sockaddr[0]).split("%", 1)[0]
        ip_obj = _try_parse_ip(raw_ip)
        if ip_obj is not None:
            norm = str(ip_obj)
            if norm not in seen:
                seen.add(norm)
                ips.append(norm)
    if not ips:
        raise OutOfScopeError(f"DNS returned no usable IP addresses for '{host}'; failing closed.")
    return ips


def _host_matches(candidate: str, entry_host: str, include_subdomains: bool) -> bool:
    if candidate == entry_host:
        return True
    return include_subdomains and candidate.endswith("." + entry_host)


def _ip_explicitly_covered(
    ip_obj: IPAddr,
    entries: list[ScopeEntry],
    *,
    unwrap_embedded: bool = False,
) -> bool:
    """Check whether an IP (or optional embedded IPv4) is covered by active ip/cidr/url entries."""
    candidates: list[IPAddr] = [ip_obj]
    if unwrap_embedded:
        embedded = _unwrap_embedded_ipv4(ip_obj)
        if embedded is not None:
            candidates.append(embedded)

    for cand in candidates:
        ip_str = str(cand)
        for entry in entries:
            if entry.type == "ip" and entry.target == ip_str:
                return True
            if entry.type == "cidr":
                net: IPNet = ipaddress.ip_network(entry.target, strict=False)
                if cand.version == net.version and cand in net:
                    return True
            if entry.type == "url_prefix":
                prefix_parsed = parse_target(entry.target)
                if prefix_parsed.is_ip and prefix_parsed.host == ip_str:
                    return True
    return False


def _match_specificity(entry: ScopeEntry, target: ParsedTarget) -> tuple[int, int]:
    """Return a descending specificity sort key (higher is more specific)."""
    if entry.type == "url_prefix":
        prefix = parse_target(entry.target)
        path_len = len((prefix.path or "/").rstrip("/"))
        exact_host = 1 if prefix.host == target.host else 0
        return (5, exact_host * 1000 + path_len)
    if entry.type == "ip":
        return (4, 0)
    if entry.type in {"domain", "onion"}:
        exact_host = 1 if entry.target == target.host else 0
        return (3 if exact_host else 2, len(entry.target))
    if entry.type == "cidr":
        net = ipaddress.ip_network(entry.target, strict=False)
        return (1, net.prefixlen)
    return (0, 0)


def entry_matches_structurally(entry: ScopeEntry, target: ParsedTarget) -> bool:
    """Check whether an active ScopeEntry matches a parsed target before DNS resolution."""
    if entry.type == "ip":
        return target.is_ip and target.host == entry.target

    if entry.type == "cidr":
        if not target.is_ip or target.ip_obj is None:
            return False
        net = ipaddress.ip_network(entry.target, strict=False)
        return target.ip_obj in net

    if entry.type in {"domain", "onion"}:
        if target.is_ip:
            return False
        return _host_matches(target.host, entry.target, entry.include_subdomains)

    if entry.type == "url_prefix":
        prefix = parse_target(entry.target)
        if target.effective_scheme() != prefix.effective_scheme():
            return False
        if target.effective_port() != prefix.effective_port():
            return False
        if prefix.is_ip:
            if not target.is_ip or target.host != prefix.host:
                return False
        else:
            if target.is_ip:
                return False
            if not _host_matches(target.host, prefix.host, entry.include_subdomains):
                return False

        prefix_path = prefix.path or "/"
        target_path = target.path or "/"
        if prefix_path == "/":
            return True
        clean_prefix = prefix_path.rstrip("/")
        return target_path == clean_prefix or target_path.startswith(clean_prefix + "/")

    return False


class ScopeManager:
    """Reads, mutates, and validates scope entries in scope.yaml."""

    def __init__(
        self,
        scope_file: Path,
        resolver: ResolverFn | None = None,
        *,
        tor_enabled: bool = False,
        tor_targets: bool = False,
        tor_proxy: str = DEFAULT_TOR_SOCKS_URL,
        tor_doh_url: str = DEFAULT_TOR_DOH_URL,
    ) -> None:
        self.scope_file = scope_file
        self.tor_enabled = tor_enabled
        self.tor_targets = tor_targets
        self.tor_proxy = tor_proxy
        self.tor_doh_url = tor_doh_url
        if resolver is not None:
            self.resolver: ResolverFn = resolver
        elif tor_enabled and tor_targets:
            self.resolver = TorDoHResolver(tor_proxy, doh_url=tor_doh_url).resolve_ips
        else:
            self.resolver = default_dns_resolver

    def load(self) -> list[ScopeEntry]:
        """Load scope entries from YAML (returns empty list if file does not exist)."""
        if not self.scope_file.exists():
            return []
        try:
            content = self.scope_file.read_text(encoding="utf-8")
            raw = yaml.safe_load(content)
        except (OSError, yaml.YAMLError) as exc:
            raise ValidationError(f"Failed to read scope file '{self.scope_file}': {exc}") from exc

        if raw is None:
            return []
        if not isinstance(raw, dict) or not isinstance(raw.get("entries", []), list):
            raise ValidationError(
                "Invalid scope.yaml format: expected mapping with 'entries' list."
            )
        return [ScopeEntry.from_dict(item) for item in raw["entries"]]

    def save(self, entries: list[ScopeEntry]) -> None:
        """Persist scope entries atomically to YAML with owner-only permissions."""
        payload = {"version": 1, "entries": [entry.to_dict() for entry in entries]}
        atomic_write_private(
            self.scope_file,
            yaml.safe_dump(payload, sort_keys=False),
            private_parent=True,
        )

    def add(
        self,
        raw_target: str,
        *,
        owner: str,
        auth_ref: str,
        expires: str,
        include_subdomains: bool = False,
        notes: str | None = None,
        replace: bool = False,
        exclude: bool = False,
    ) -> ScopeEntry:
        """Add a new normalized entry to scope.yaml (or replace matching active target)."""
        if not owner.strip():
            raise ValidationError("Scope entry 'owner' must not be empty.")
        if not auth_ref.strip():
            raise ValidationError("Scope entry 'auth_ref' must not be empty.")
        parse_expiry(expires)

        entry_type, norm_target, sub_flag = parse_scope_spec(
            raw_target, include_subdomains=include_subdomains
        )
        entries = self.load()
        matching_active = [
            e
            for e in entries
            if not e.is_expired()
            and e.type == entry_type
            and e.target.lower() == norm_target.lower()
            and e.exclude == exclude
        ]
        if matching_active and not replace:
            existing = matching_active[0]
            raise ValidationError(
                f"Active scope entry '{existing.id}' already exists for '{norm_target}'. "
                "Remove it first or pass --replace."
            )
        if replace:
            entries = [
                e
                for e in entries
                if not (
                    e.type == entry_type
                    and e.target.lower() == norm_target.lower()
                    and e.exclude == exclude
                )
            ]
        new_entry = ScopeEntry(
            id=uuid.uuid4().hex[:8],
            target=norm_target,
            type=entry_type,
            include_subdomains=sub_flag,
            owner=owner.strip(),
            auth_ref=auth_ref.strip(),
            created_at=utc_now_iso(),
            expires_at=expires.strip(),
            notes=notes.strip() if notes else None,
            exclude=exclude,
        )
        entries.append(new_entry)
        self.save(entries)
        return new_entry

    def import_targets(
        self,
        raw_lines: list[str],
        *,
        source: str,
        owner: str,
        auth_ref: str,
        expires: str,
        include_subdomains: bool = False,
        notes: str | None = None,
        replace: bool = False,
        exclude: bool = False,
        dry_run: bool = False,
    ) -> ScopeImportResult:
        """Bulk-import newline-delimited targets (prefix `!` marks per-line exclusions)."""
        if not owner.strip():
            raise ValidationError("Scope entry 'owner' must not be empty.")
        if not auth_ref.strip():
            raise ValidationError("Scope entry 'auth_ref' must not be empty.")
        parse_expiry(expires)

        entries = self.load()
        added: list[ScopeEntry] = []
        skipped: list[str] = []
        errors: list[str] = []

        for line_no, raw_line in enumerate(raw_lines, start=1):
            stripped = raw_line.split("#", 1)[0].strip()
            if not stripped:
                continue
            line_exclude = exclude
            target_text = stripped
            if target_text.startswith("!"):
                line_exclude = True
                target_text = target_text[1:].strip()
            if not target_text:
                continue

            try:
                entry_type, norm_target, sub_flag = parse_scope_spec(
                    target_text, include_subdomains=include_subdomains
                )
            except ValidationError as exc:
                errors.append(f"Line {line_no} ({target_text}): {exc}")
                continue

            matching_active = [
                e
                for e in entries
                if not e.is_expired()
                and e.type == entry_type
                and e.target.lower() == norm_target.lower()
                and e.exclude == line_exclude
            ]
            if matching_active and not replace:
                skipped.append(norm_target)
                continue
            if replace:
                entries = [
                    e
                    for e in entries
                    if not (
                        e.type == entry_type
                        and e.target.lower() == norm_target.lower()
                        and e.exclude == line_exclude
                    )
                ]

            new_entry = ScopeEntry(
                id=uuid.uuid4().hex[:8],
                target=norm_target,
                type=entry_type,
                include_subdomains=sub_flag,
                owner=owner.strip(),
                auth_ref=auth_ref.strip(),
                created_at=utc_now_iso(),
                expires_at=expires.strip(),
                notes=notes.strip() if notes else None,
                exclude=line_exclude,
            )
            entries.append(new_entry)
            added.append(new_entry)

        if added and not dry_run:
            self.save(entries)

        return ScopeImportResult(
            source=source,
            dry_run=dry_run,
            added=added,
            skipped=skipped,
            errors=errors,
        )

    def remove(self, identifier: str) -> list[ScopeEntry]:
        """Remove entries matching an ID or exact target string; return removed entries."""
        entries = self.load()
        needle = identifier.strip()
        needle_lower = needle.lower()
        kept: list[ScopeEntry] = []
        removed: list[ScopeEntry] = []
        for entry in entries:
            if entry.id == needle or entry.target == needle or entry.target.lower() == needle_lower:
                removed.append(entry)
            else:
                kept.append(entry)
        if removed:
            self.save(kept)
        return removed

    def expire(self, *, prune: bool = False, now: datetime | None = None) -> list[ScopeEntry]:
        """Return expired entries and optionally remove them from scope.yaml."""
        entries = self.load()
        expired = [e for e in entries if e.is_expired(now=now)]
        if prune and expired:
            active = [e for e in entries if not e.is_expired(now=now)]
            self.save(active)
        return expired

    def check_target(self, raw_target: str, *, now: datetime | None = None) -> ScopeCheckResult:
        """Evaluate target against active scope entries, exclusions, and live DNS resolution."""
        parsed = parse_target(raw_target)
        entries = self.load()
        active_entries = [e for e in entries if not e.is_expired(now=now)]
        exclude_entries = [e for e in active_entries if e.exclude]
        allow_entries = [e for e in active_entries if not e.exclude]

        # Exclusions take strict precedence over allow entries (before any DNS lookup).
        excluded_matches = sorted(
            (e for e in exclude_entries if entry_matches_structurally(e, parsed)),
            key=lambda e: _match_specificity(e, parsed),
            reverse=True,
        )
        if excluded_matches:
            denied = excluded_matches[0]
            return ScopeCheckResult(
                in_scope=False,
                parsed_target=parsed,
                matched_entry=None,
                resolved_ips=[],
                pinned_ip=None,
                reason=(
                    f"Target '{raw_target}' is explicitly excluded by scope entry "
                    f"'{denied.id}' ({denied.target})."
                ),
            )

        if (
            parsed.is_ip
            and parsed.ip_obj is not None
            and _ip_explicitly_covered(parsed.ip_obj, exclude_entries, unwrap_embedded=True)
        ):
            return ScopeCheckResult(
                in_scope=False,
                parsed_target=parsed,
                matched_entry=None,
                resolved_ips=[],
                pinned_ip=None,
                reason=(
                    f"Target '{raw_target}' maps to an explicitly excluded IP address in scope."
                ),
            )

        structural_matches = sorted(
            (e for e in allow_entries if entry_matches_structurally(e, parsed)),
            key=lambda e: _match_specificity(e, parsed),
            reverse=True,
        )
        if not structural_matches:
            expired_matches = [
                e
                for e in entries
                if not e.exclude and e.is_expired(now=now) and entry_matches_structurally(e, parsed)
            ]
            reason = (
                f"Matched scope entry '{expired_matches[0].id}' is expired "
                f"({expired_matches[0].expires_at})."
                if expired_matches
                else f"Target '{raw_target}' does not match any active entry in {self.scope_file}."
            )
            return ScopeCheckResult(
                in_scope=False,
                parsed_target=parsed,
                matched_entry=None,
                resolved_ips=[],
                pinned_ip=None,
                reason=reason,
            )

        matched = structural_matches[0]

        # Authorized Tor v3 `.onion` targets skip clearnet DNS entirely (zero DNS leak)
        if not parsed.is_ip and is_v3_onion_host(parsed.host):
            if not self.tor_enabled:
                return ScopeCheckResult(
                    in_scope=False,
                    parsed_target=parsed,
                    matched_entry=matched,
                    resolved_ips=[],
                    pinned_ip=None,
                    reason=(
                        f"Authorized .onion target '{parsed.host}' requires `--tor` "
                        "(SOCKS5h routing; clearnet DNS is never queried for .onion)."
                    ),
                )
            return ScopeCheckResult(
                in_scope=True,
                parsed_target=parsed,
                matched_entry=matched,
                resolved_ips=["tor-onion"],
                pinned_ip="tor-onion",
                reason=(
                    f"Authorized v3 .onion target by scope entry '{matched.id}' "
                    f"({matched.auth_ref}) via Tor SOCKS5h."
                ),
            )

        # Tor target routing is strictly limited to public clearnet targets (never private/CGNAT)
        if (
            self.tor_enabled
            and self.tor_targets
            and parsed.is_ip
            and parsed.ip_obj is not None
            and is_special_ip(parsed.ip_obj)
        ):
            return ScopeCheckResult(
                in_scope=False,
                parsed_target=parsed,
                matched_entry=matched,
                resolved_ips=[str(parsed.ip_obj)],
                pinned_ip=None,
                reason=(
                    f"Target IP '{parsed.ip_obj}' is private/special and cannot be routed "
                    "through `--tor --tor-targets`."
                ),
            )

        if parsed.is_ip and parsed.ip_obj is not None:
            resolved_ips = [str(parsed.ip_obj)]
        else:
            try:
                resolved_ips = self.resolver(parsed.host)
            except OutOfScopeError as exc:
                return ScopeCheckResult(
                    in_scope=False,
                    parsed_target=parsed,
                    matched_entry=matched,
                    resolved_ips=[],
                    pinned_ip=None,
                    reason=str(exc),
                )

        if not parsed.is_ip:
            for ip_str in resolved_ips:
                ip_obj = _try_parse_ip(ip_str)
                if ip_obj is None:
                    return ScopeCheckResult(
                        in_scope=False,
                        parsed_target=parsed,
                        matched_entry=matched,
                        resolved_ips=resolved_ips,
                        pinned_ip=None,
                        reason=f"Invalid resolved IP '{ip_str}' for '{parsed.host}'.",
                    )
                if _ip_explicitly_covered(ip_obj, exclude_entries, unwrap_embedded=True):
                    return ScopeCheckResult(
                        in_scope=False,
                        parsed_target=parsed,
                        matched_entry=None,
                        resolved_ips=resolved_ips,
                        pinned_ip=None,
                        reason=(
                            f"Target '{parsed.host}' resolved to explicitly excluded IP '{ip_str}'."
                        ),
                    )
                if self.tor_enabled and self.tor_targets and is_special_ip(ip_obj):
                    return ScopeCheckResult(
                        in_scope=False,
                        parsed_target=parsed,
                        matched_entry=matched,
                        resolved_ips=resolved_ips,
                        pinned_ip=None,
                        reason=(
                            f"Target '{parsed.host}' resolved to private/special IP '{ip_str}', "
                            "which is forbidden under `--tor --tor-targets`."
                        ),
                    )
                if is_special_ip(ip_obj) and not _ip_explicitly_covered(ip_obj, allow_entries):
                    return ScopeCheckResult(
                        in_scope=False,
                        parsed_target=parsed,
                        matched_entry=matched,
                        resolved_ips=resolved_ips,
                        pinned_ip=None,
                        reason=(
                            f"Target '{parsed.host}' resolved to special/private IP '{ip_str}' "
                            "which is not explicitly authorized in scope."
                        ),
                    )

        return ScopeCheckResult(
            in_scope=True,
            parsed_target=parsed,
            matched_entry=matched,
            resolved_ips=resolved_ips,
            pinned_ip=resolved_ips[0],
            reason=f"Authorized by scope entry '{matched.id}' ({matched.auth_ref}).",
        )
