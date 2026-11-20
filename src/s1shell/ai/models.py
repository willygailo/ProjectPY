"""Canonical dataclasses for `s1shell ai` environment and analysis artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class AIEnvStatus:
    """Safe status report for AI provider, API key, and model configuration."""

    configured: bool
    masked_key: str | None
    key_type: str  # unset | standard | admin | custom | local
    source: str
    model: str
    env_file: str
    note: str
    provider: str = "anthropic"
    base_url: str = ""
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_env_report"


@dataclass(frozen=True)
class AIAnalysisResult:
    """Canonical result of a defensive `s1shell ai analyze` run."""

    model: str
    task: str
    input_artifacts: list[str]
    analysis: str
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str = "anthropic"
    mode: str = "triage"
    redacted: bool = False
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_analysis_report"
