"""Defensive Tor SOCKS5h transport, zero-DNS-leak DoH resolver, and diagnostics."""

from __future__ import annotations

import importlib.util
import ipaddress
import re
import shutil
import socket
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import dns.resolver
import httpx

from s1shell import __version__
from s1shell.errors import NetworkError, OutOfScopeError, ValidationError
from s1shell.models import SCHEMA_VERSION, utc_now_iso

DEFAULT_TOR_SOCKS_URL = "socks5h://127.0.0.1:9050"
TOR_BROWSER_SOCKS_URL = "socks5h://127.0.0.1:9150"
DEFAULT_TOR_DOH_URL = "https://cloudflare-dns.com/dns-query"
FALLBACK_TOR_DOH_URL = "https://dns.google/resolve"
TOR_CHECK_API_URL = "https://check.torproject.org/api/ip"

_V3_ONION_LABEL_RE = re.compile(r"^[a-z2-7]{56}$")
_SUBDOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

_RDTYPE_NUMS: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DS": 43,
    "TLSA": 52,
    "CAA": 257,
}


@dataclass(frozen=True)
class TorStatusResult:
    """Offline local Tor daemon & dependency readiness report."""

    tor_binary: str | None
    socksio_available: bool
    configured_proxy: str
    reachable: bool
    active_proxy: str | None
    detail: str
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "tor_status_report"


@dataclass(frozen=True)
class TorCheckResult:
    """Online Tor egress verification via check.torproject.org over SOCKS5h."""

    proxy_url: str
    is_tor: bool
    exit_ip: str | None
    latency_ms: int
    detail: str
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "tor_check_report"


def is_loopback_host(host: str) -> bool:
    """Return True if `host` strictly refers to localhost, 127.0.0.0/8, or ::1."""
    clean = host.strip().lower().strip("[]").rstrip(".")
    if clean == "localhost":
        return True
    try:
        return ipaddress.ip_address(clean).is_loopback
    except ValueError:
        return False


def is_onion_host(host: str) -> bool:
    """Return True if a hostname ends in `.onion` (RFC 7686)."""
    clean = host.strip().lower().rstrip(".")
    return clean == "onion" or clean.endswith(".onion")


def is_v3_onion_host(host: str) -> bool:
    """Return True strictly for valid 56-char base32 Tor v3 `.onion` hosts (optional subdomains)."""
    clean = host.strip().lower().rstrip(".")
    if not clean.endswith(".onion"):
        return False
    labels = clean.split(".")
    if len(labels) < 2 or labels[-1] != "onion":
        return False
    if not _V3_ONION_LABEL_RE.match(labels[-2]):
        return False
    return all(_SUBDOMAIN_LABEL_RE.match(lbl) for lbl in labels[:-2])


def socksio_installed() -> bool:
    """Return True when the `socksio` package required by httpx SOCKS5h is importable."""
    return importlib.util.find_spec("socksio") is not None


def validate_tor_proxy_url(url: str, *, require_socksio: bool = True) -> str:
    """Validate a local Tor SOCKS5h proxy URL (blocks DNS-leaking schemes & remote hosts)."""
    cleaned = url.strip()
    parts = urlsplit(cleaned)
    if parts.scheme.lower() != "socks5h":
        raise ValidationError(
            f"Tor proxy '{url}' must use the `socks5h://` scheme (not `{parts.scheme or 'none'}`) "
            "to prevent local DNS leaks."
        )
    host = (parts.hostname or "").strip().lower()
    if not host or not is_loopback_host(host):
        raise ValidationError(
            f"Tor proxy host '{host or url}' must be a local loopback address "
            "(127.0.0.1, localhost, or ::1)."
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"Invalid Tor proxy port in '{url}': {exc}") from exc
    if port is None or port < 1 or port > 65535:
        raise ValidationError(f"Tor proxy URL '{url}' must specify a valid TCP port (e.g. 9050).")
    if require_socksio and not socksio_installed():
        raise ValidationError(
            "Tor SOCKS5h routing requires `socksio`. "
            "Install with: `pip install 'httpx[http2,socks]'`."
        )
    host_fmt = f"[{host}]" if ":" in host else host
    return f"socks5h://{host_fmt}:{port}"


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("Unexpected EOF from Tor SOCKS5h proxy.")
        buf.extend(chunk)
    return bytes(buf)


def open_socks5h_socket(
    proxy_url: str,
    *,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Open a TCP stream through local SOCKS5h using RFC 1928 ATYP 0x03 (zero DNS leak)."""
    validated = validate_tor_proxy_url(proxy_url, require_socksio=False)
    parts = urlsplit(validated)
    proxy_host = parts.hostname or "127.0.0.1"
    proxy_port = parts.port or 9050

    host_bytes = target_host.strip().encode("idna")
    if not host_bytes or len(host_bytes) > 255:
        raise ValidationError(f"Invalid target host for SOCKS5h tunnel: '{target_host}'.")

    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        sock.settimeout(timeout)

        # Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise NetworkError(
                f"Tor SOCKS5h proxy at {proxy_host}:{proxy_port} rejected handshake."
            )

        # Request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (DOMAINNAME), LEN, HOST, PORT
        req = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", target_port)
        )
        sock.sendall(req)

        header = _recv_exact(sock, 4)
        if header[0] != 5:
            raise NetworkError("Invalid SOCKS5 reply version from Tor proxy.")
        rep = header[1]
        if rep != 0:
            raise NetworkError(
                f"Tor SOCKS5h CONNECT failed for '{target_host}:{target_port}' "
                f"(SOCKS reply 0x{rep:02x})."
            )

        atyp = header[3]
        if atyp == 1:  # IPv4
            _recv_exact(sock, 6)
        elif atyp == 4:  # IPv6
            _recv_exact(sock, 18)
        elif atyp == 3:  # Domain
            dlen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, dlen + 2)
        else:
            raise NetworkError(f"Unexpected SOCKS5 reply ATYP 0x{atyp:02x}.")
        return sock
    except NetworkError:
        if sock is not None:
            sock.close()
        raise
    except OSError as exc:
        if sock is not None:
            sock.close()
        raise NetworkError(
            f"Tor SOCKS5h proxy at {proxy_host}:{proxy_port} is unreachable "
            f"(fail-closed; no clearnet fallback): {exc}"
        ) from exc


class TorDoHResolver:
    """Zero-DNS-leak DNS-over-HTTPS resolver tunneled strictly over Tor SOCKS5h."""

    def __init__(
        self,
        proxy_url: str = DEFAULT_TOR_SOCKS_URL,
        *,
        doh_url: str = DEFAULT_TOR_DOH_URL,
        fallback_doh_url: str | None = FALLBACK_TOR_DOH_URL,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.proxy_url = validate_tor_proxy_url(proxy_url, require_socksio=(transport is None))
        self.doh_url = doh_url
        self.fallback_doh_url = fallback_doh_url
        self.timeout = timeout
        self._transport = transport

    def _query_doh_json(self, qname: str, rdtype: str, timeout: float) -> dict[str, object]:
        endpoints = [self.doh_url]
        if self.fallback_doh_url and self.fallback_doh_url != self.doh_url:
            endpoints.append(self.fallback_doh_url)

        last_err: Exception | None = None
        client_kwargs: dict[str, object] = {
            "timeout": httpx.Timeout(timeout),
            "follow_redirects": False,
            "trust_env": False,
            "http2": True,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport
        else:
            client_kwargs["proxy"] = self.proxy_url

        with httpx.Client(**client_kwargs) as client:  # type: ignore[arg-type]
            for url in endpoints:
                try:
                    resp = client.get(
                        url,
                        params={"name": qname, "type": rdtype},
                        headers={"Accept": "application/dns-json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict):
                            return data
                    last_err = NetworkError(
                        f"DoH endpoint '{url}' returned HTTP {resp.status_code}."
                    )
                except (httpx.HTTPError, ValueError) as exc:
                    last_err = exc
                    continue

        raise NetworkError(
            f"Tor DoH lookup failed for '{qname}' ({rdtype}) — fail-closed (zero local DNS leak): "
            f"{last_err}"
        )

    def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
        """Resolve DNS records via DoH over Tor (compatible with `dns_check.RecordResolver`)."""
        norm_type = rdtype.strip().upper()
        payload = self._query_doh_json(
            qname.strip().rstrip("."), norm_type, max(lifetime, self.timeout)
        )
        status = int(payload.get("Status", 0) or 0)  # type: ignore[call-overload]
        if status == 3:
            raise dns.resolver.NXDOMAIN
        if status != 0:
            raise dns.resolver.NoAnswer

        raw_answers = payload.get("Answer")
        if not isinstance(raw_answers, list) or not raw_answers:
            raise dns.resolver.NoAnswer

        expected_code = _RDTYPE_NUMS.get(norm_type)
        records: list[str] = []
        for ans in raw_answers:
            if not isinstance(ans, dict):
                continue
            ans_type = ans.get("type")
            if expected_code is not None and ans_type != expected_code:
                continue
            data_val = str(ans.get("data") or "").strip().rstrip(".")
            if data_val:
                records.append(data_val)

        if not records:
            raise dns.resolver.NoAnswer
        return records

    def resolve_ips(self, host: str) -> list[str]:
        """Resolve A/AAAA IPs via Tor DoH for fail-closed scope anti-SSRF validation."""
        ips: list[str] = []
        seen: set[str] = set()
        had_network_err: Exception | None = None

        for rdtype in ("A", "AAAA"):
            try:
                recs = self.resolve(host, rdtype, lifetime=self.timeout)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except NetworkError as exc:
                had_network_err = exc
                continue
            for item in recs:
                try:
                    ip_obj = ipaddress.ip_address(item)
                except ValueError:
                    continue
                norm = str(ip_obj)
                if norm not in seen:
                    seen.add(norm)
                    ips.append(norm)

        if not ips:
            if had_network_err is not None:
                raise OutOfScopeError(
                    f"Tor DoH resolution failed for '{host}'; failing closed: {had_network_err}"
                ) from had_network_err
            raise OutOfScopeError(
                f"Tor DoH returned no usable IP addresses for '{host}'; failing closed."
            )
        return ips


def _tcp_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_local_tor_port(
    proxy_url: str = DEFAULT_TOR_SOCKS_URL,
    *,
    timeout: float = 1.0,
) -> TorStatusResult:
    """Offline local check for Tor binary, `socksio`, and local SOCKS5h port reachability."""
    validated = validate_tor_proxy_url(proxy_url, require_socksio=False)
    parts = urlsplit(validated)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 9050

    tor_bin = shutil.which("tor")
    has_socksio = socksio_installed()
    reachable = _tcp_port_open(host, port, timeout)
    active_proxy: str | None = validated if reachable else None

    if (
        not reachable
        and validated == DEFAULT_TOR_SOCKS_URL
        and _tcp_port_open("127.0.0.1", 9150, timeout)
    ):
        reachable = True
        active_proxy = TOR_BROWSER_SOCKS_URL

    if reachable and has_socksio:
        detail = f"Tor SOCKS5h proxy reachable at {active_proxy} (socksio ready)"
    elif reachable and not has_socksio:
        detail = (
            f"Tor SOCKS5h listening at {active_proxy}, but `socksio` is missing "
            "(install `pip install 'httpx[http2,socks]'`)."
        )
    else:
        detail = (
            f"Tor SOCKS5h proxy not reachable at {validated} "
            "(start Tor on Kali with: `sudo systemctl enable --now tor`)."
        )

    return TorStatusResult(
        tor_binary=tor_bin,
        socksio_available=has_socksio,
        configured_proxy=validated,
        reachable=reachable,
        active_proxy=active_proxy,
        detail=detail,
    )


def verify_tor_egress(
    proxy_url: str = DEFAULT_TOR_SOCKS_URL,
    *,
    timeout: float = 15.0,
    transport: httpx.BaseTransport | None = None,
) -> TorCheckResult:
    """Verify live Tor egress through `check.torproject.org/api/ip` (fail-closed if Tor is down)."""
    validated = validate_tor_proxy_url(proxy_url, require_socksio=(transport is None))
    started = time.monotonic()
    client_kwargs: dict[str, object] = {
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": False,
        "trust_env": False,
        "http2": True,
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    else:
        client_kwargs["proxy"] = validated

    try:
        with httpx.Client(**client_kwargs) as client:  # type: ignore[arg-type]
            resp = client.get(TOR_CHECK_API_URL, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise NetworkError(
            f"Tor egress check failed via {validated} (fail-closed; no clearnet fallback): {exc}"
        ) from exc

    latency_ms = int((time.monotonic() - started) * 1000)
    if resp.status_code != 200:
        raise NetworkError(
            f"Tor egress check endpoint returned HTTP {resp.status_code} via {validated}."
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise NetworkError(f"Tor egress check returned non-JSON payload: {exc}") from exc

    is_tor = bool(payload.get("IsTor", False)) if isinstance(payload, dict) else False
    exit_ip = str(payload.get("IP") or "").strip() or None if isinstance(payload, dict) else None
    if not is_tor:
        raise NetworkError(
            f"Proxy {validated} reached check.torproject.org, but IsTor=false (IP={exit_ip}). "
            "Refusing to treat egress as Tor."
        )

    return TorCheckResult(
        proxy_url=validated,
        is_tor=True,
        exit_ip=exit_ip,
        latency_ms=latency_ms,
        detail=f"Confirmed Tor exit egress ({exit_ip or 'unknown'}) in {latency_ms} ms.",
    )
