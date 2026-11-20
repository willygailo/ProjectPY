"""Shared canonical schemas and serialization helpers across S1shell artifacts."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return current UTC timestamp formatted in ISO-8601 Z notation."""
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_json_compatible(value: Any) -> Any:
    """Recursively convert dataclasses, Paths, Enums, and datetimes into JSON-safe objects."""
    if is_dataclass(value) and not isinstance(value, type):
        return {k: to_json_compatible(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json_compatible(v) for v in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(
        value,
        (
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network,
        ),
    ):
        return str(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def dumps_json(value: Any, *, indent: int | None = 2) -> str:
    """Serialize an arbitrary S1shell dataclass/dict to formatted JSON."""
    return json.dumps(to_json_compatible(value), indent=indent, sort_keys=False)
