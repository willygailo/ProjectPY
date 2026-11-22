"""Authorized target evidence & surface artifact exporter (`s1shell dump`)."""

from __future__ import annotations

from s1shell.dump.exporter import export_evidence_bundle, extract_surface_entities
from s1shell.dump.models import DumpFileEntry, DumpResult
from s1shell.dump.service import DumpService

__all__ = [
    "DumpFileEntry",
    "DumpResult",
    "DumpService",
    "export_evidence_bundle",
    "extract_surface_entities",
]
