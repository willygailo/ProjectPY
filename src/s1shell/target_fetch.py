"""Shared guarded TLS + single-GET target snapshot helper."""

from __future__ import annotations

import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import httpx

from s1shell.config import RuntimeConfig
from s1shell.http import BoundedResponse, PinnedHTTPTransport, build_target_client, fetch_bounded
from s1shell.profile.models import TLSResult
from s1shell.scope import ParsedTarget

TLSInspectorFn = Callable[..., tuple[TLSResult, str | None]]


@dataclass(frozen=True)
class TargetSnapshot:
    """Result of a single guarded TLS handshake + bounded HTTP GET."""

    url: str
    is_https: bool
    tls: TLSResult | None
    alpn_protocol: str | None
    response: BoundedResponse
    connected_ip: str | None = None


def fetch_target_snapshot(
    cfg: RuntimeConfig,
    *,
    parsed: ParsedTarget,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    tls_inspector: TLSInspectorFn,
    http_transport: httpx.BaseTransport | None = None,
    cafile: str | None = None,
    check_tls_versions: bool = False,
) -> TargetSnapshot:
    """Perform optional single TLS inspection followed by a single IP-pinned GET."""
    scheme = parsed.effective_scheme("https")
    is_https = scheme == "https"
    port = parsed.effective_port("https")
    url = parsed.to_url("https")
    validated_ips = list(dict.fromkeys([pinned_ip, *(pinned_ips or [])]))
    effective_ip = pinned_ip

    tls_result: TLSResult | None = None
    alpn_proto: str | None = None
    if is_https:
        last_tls_exc: Exception | None = None
        for idx, candidate_ip in enumerate(validated_ips):
            try:
                tls_result, alpn_proto = tls_inspector(
                    host=parsed.host,
                    pinned_ip=candidate_ip,
                    port=port,
                    timeout=cfg.timeout_seconds,
                    is_ip=parsed.is_ip,
                    cafile=cafile,
                    check_versions=check_tls_versions,
                )
                effective_ip = candidate_ip
                last_tls_exc = None
                break
            except Exception as exc:
                last_tls_exc = exc
                if idx == len(validated_ips) - 1:
                    raise
        if last_tls_exc is not None:
            raise last_tls_exc

    verify_arg: ssl.SSLContext | bool = True
    if cafile is not None:
        verify_arg = ssl.create_default_context(cafile=cafile)
    elif tls_result is not None and not tls_result.verified:
        # TLS verification status was already recorded explicitly in tls_result;
        # allow capturing the single HTTP response headers even for self-signed labs.
        verify_arg = False

    ordered_http_ips = list(dict.fromkeys([effective_ip, *validated_ips]))
    pinned_transport: PinnedHTTPTransport | None = None
    chosen_transport = http_transport
    if chosen_transport is None:
        pinned_transport = PinnedHTTPTransport(
            expected_host=parsed.host,
            pinned_ip=effective_ip,
            pinned_ips=ordered_http_ips,
            verify=verify_arg,
            http2=True,
        )
        chosen_transport = pinned_transport

    with build_target_client(
        cfg,
        expected_host=parsed.host,
        pinned_ip=effective_ip,
        pinned_ips=ordered_http_ips,
        verify=verify_arg,
        transport=chosen_transport,
    ) as client:
        resp = fetch_bounded(
            client,
            "GET",
            url,
            max_bytes=cfg.max_response_bytes,
        )

    connected_ip = pinned_transport.connected_ip if pinned_transport is not None else effective_ip
    return TargetSnapshot(
        url=url,
        is_https=is_https,
        tls=tls_result,
        alpn_protocol=alpn_proto,
        response=resp,
        connected_ip=connected_ip,
    )
