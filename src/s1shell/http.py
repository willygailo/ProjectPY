"""Guarded HTTP client factory enforcing pinned IPs, no redirects, and size caps."""

from __future__ import annotations

import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TypeAlias

import httpcore
import httpx

from s1shell.config import RuntimeConfig
from s1shell.errors import NetworkError
from s1shell.tor import validate_tor_proxy_url

SocketOption: TypeAlias = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)


class PinnedSyncBackend(httpcore.SyncBackend):
    """Network backend that pins TCP connections for expected_host to validated scope IPs."""

    def __init__(
        self,
        *,
        expected_host: str,
        pinned_ip: str,
        pinned_ips: Sequence[str] | None = None,
    ) -> None:
        self._expected_host = expected_host.lower()
        candidates = list(dict.fromkeys([pinned_ip, *(pinned_ips or [])]))
        self._pinned_ips: list[str] = [ip for ip in candidates if ip]
        self._pinned_ip = self._pinned_ips[0] if self._pinned_ips else pinned_ip
        self.connected_ip: str = self._pinned_ip

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        if host.lower() != self._expected_host and host not in self._pinned_ips:
            raise httpcore.ConnectError(
                f"Refused unpinned connection to '{host}'; expected '{self._expected_host}'."
            )
        last_exc: Exception | None = None
        for ip in self._pinned_ips:
            try:
                stream = super().connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                self.connected_ip = ip
                return stream
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
                continue
        if last_exc is not None:
            raise last_exc
        raise httpcore.ConnectError(f"No validated IP available for '{self._expected_host}'.")


class PinnedHTTPTransport(httpx.HTTPTransport):
    """httpx transport pinning connections to verified scope IPs while preserving SNI/Host."""

    def __init__(
        self,
        *,
        expected_host: str,
        pinned_ip: str,
        pinned_ips: Sequence[str] | None = None,
        verify: ssl.SSLContext | bool = True,
        http2: bool = True,
    ) -> None:
        super().__init__(verify=verify, trust_env=False, http1=True, http2=http2, retries=0)
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
        self._backend = PinnedSyncBackend(
            expected_host=expected_host,
            pinned_ip=pinned_ip,
            pinned_ips=pinned_ips,
        )
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=http2,
            retries=0,
            network_backend=self._backend,
        )

    @property
    def connected_ip(self) -> str:
        """Return the validated IP actually used for the TCP connection."""
        return self._backend.connected_ip


@dataclass(frozen=True)
class BoundedResponse:
    """Result of a size-capped single HTTP request."""

    status_code: int
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool


def build_target_client(
    cfg: RuntimeConfig,
    *,
    expected_host: str,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    verify: ssl.SSLContext | bool = True,
    transport: httpx.BaseTransport | None = None,
    tor_proxy: str | None = None,
) -> httpx.Client:
    """Create a read-only, non-redirecting httpx client (IP-pinned direct or Tor SOCKS5h)."""
    if transport is None and tor_proxy is not None:
        validated_proxy = validate_tor_proxy_url(tor_proxy)
        return httpx.Client(
            proxy=validated_proxy,
            verify=verify,
            headers={"User-Agent": cfg.user_agent},
            timeout=httpx.Timeout(cfg.timeout_seconds),
            follow_redirects=False,
            max_redirects=0,
            trust_env=False,
            http2=True,
        )

    chosen_transport = (
        transport
        if transport is not None
        else PinnedHTTPTransport(
            expected_host=expected_host,
            pinned_ip=pinned_ip,
            pinned_ips=pinned_ips,
            verify=verify,
            http2=True,
        )
    )
    return httpx.Client(
        transport=chosen_transport,
        headers={"User-Agent": cfg.user_agent},
        timeout=httpx.Timeout(cfg.timeout_seconds),
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
    )


def build_intel_client(
    cfg: RuntimeConfig,
    *,
    transport: httpx.BaseTransport | None = None,
    follow_redirects: bool = False,
    bypass_tor: bool = False,
) -> httpx.Client:
    """Create a conservative httpx client for public intel/CVE/AI APIs (optional Tor SOCKS5h)."""
    if transport is None and cfg.tor_enabled and not bypass_tor:
        validated_proxy = validate_tor_proxy_url(cfg.tor_proxy)
        return httpx.Client(
            proxy=validated_proxy,
            headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
            timeout=httpx.Timeout(cfg.timeout_seconds),
            follow_redirects=follow_redirects,
            max_redirects=3 if follow_redirects else 0,
            http2=True,
            trust_env=False,
        )
    return httpx.Client(
        transport=transport,
        headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
        timeout=httpx.Timeout(cfg.timeout_seconds),
        follow_redirects=follow_redirects,
        max_redirects=3 if follow_redirects else 0,
        http2=True,
    )


def fetch_bounded(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None = None,
) -> BoundedResponse:
    """Execute one HTTP request and read at most `max_bytes` of the response body."""
    if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError(f"Disallowed HTTP method '{method}'. Only GET, HEAD, OPTIONS allowed.")

    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        with client.stream(method.upper(), url, headers=headers) as resp:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                remaining = max_bytes - total
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    total += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)

            raw_headers = list(resp.headers.raw)
            decoded_headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in raw_headers]
            return BoundedResponse(
                status_code=resp.status_code,
                http_version=resp.http_version,
                headers=decoded_headers,
                body=b"".join(chunks),
                truncated=truncated,
            )
    except httpx.HTTPError as exc:
        raise NetworkError(f"HTTP request failed for '{url}': {exc}") from exc
