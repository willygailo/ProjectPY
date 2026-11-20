"""Canonical dataclasses for `s1shell codec` offline decode, encode, inspect, and hash outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class CodecStep:
    """One transform stage executed during single, chained, or auto decoding/encoding."""

    stage: int
    codec: str
    input_bytes: int
    output_bytes: int
    note: str = ""


@dataclass(frozen=True)
class CodecTransformResult:
    """Canonical output envelope for `s1shell codec decode` and `s1shell codec encode`."""

    operation: str  # decode | encode
    steps: list[CodecStep]
    output_text: str
    output_hex: str
    output_base64: str
    is_utf8: bool
    byte_length: int
    sha256: str
    entropy: float
    variants: list[dict[str, str]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "codec_transform"


@dataclass(frozen=True)
class CodecInspectResult:
    """Canonical output envelope for `s1shell codec inspect` smart offline analyzer."""

    detected_types: list[str]
    byte_length: int
    sha256: str
    entropy: float
    jwt: dict[str, Any] | None = None
    x509: dict[str, Any] | None = None
    hash_candidates: list[dict[str, str]] = field(default_factory=list)
    timestamp_utc: str | None = None
    auto_decoded: CodecTransformResult | None = None
    notes: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "codec_inspect"


@dataclass(frozen=True)
class CodecHashResult:
    """Canonical output envelope for `s1shell codec hash` multi-algorithm digest output."""

    source: str
    byte_length: int
    entropy: float
    hashes: dict[str, str] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "codec_hash"
