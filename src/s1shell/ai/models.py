"""Canonical dataclasses for `s1shell ai` environment, analysis, pipeline, and investigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.ai.verify import GroundingReport
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class AIEnvStatus:
    """Safe status report for AI provider, API key, and model configuration."""

    configured: bool
    masked_key: str | None
    key_type: str  # unset | standard | user | admin | custom | local
    source: str
    model: str
    env_file: str
    note: str
    provider: str = "anthropic"
    base_url: str = ""
    workspace_id: str | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_env_report"


@dataclass(frozen=True)
class AIPipelineStageResult:
    """Telemetry summary for one stage of a multi-stage AI reasoning pipeline."""

    stage: str
    role: str
    input_tokens: int = 0
    output_tokens: int = 0
    preview: str = ""


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
    skill: str | None = None
    pipeline: str | None = None
    pipeline_stages: list[AIPipelineStageResult] = field(default_factory=list)
    structured_data: dict[str, Any] | None = None
    redactions_applied: int = 0
    restored: bool = False
    cached: bool = False
    fallback_used: str | None = None
    injection_warnings: list[str] = field(default_factory=list)
    grounding: GroundingReport | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_analysis_report"


@dataclass(frozen=True)
class AIInvestigationStep:
    """Single bounded step executed by the read-only ReAct AI investigator."""

    step: int
    thought: str
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    observation_preview: str = ""
    error: str | None = None


@dataclass(frozen=True)
class AIInvestigationResult:
    """Canonical result of a bounded read-only `s1shell ai investigate` session."""

    model: str
    provider: str
    goal: str
    input_artifacts: list[str]
    final_answer: str
    steps: list[AIInvestigationStep] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    redacted: bool = False
    restored: bool = False
    redactions_applied: int = 0
    injection_warnings: list[str] = field(default_factory=list)
    grounding: GroundingReport | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_investigation_report"
