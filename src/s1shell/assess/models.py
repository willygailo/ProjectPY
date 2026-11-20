"""Canonical dataclasses for `s1shell assess`, batch runs, remediation plans, and diffs."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.ai.models import AIAnalysisResult
from s1shell.cve.models import CVESearchResult
from s1shell.fingerprint.models import FingerprintResult
from s1shell.models import SCHEMA_VERSION, utc_now_iso
from s1shell.profile.models import ProfileResult


@dataclass(frozen=True)
class AssessmentFinding:
    """Single prioritized security finding derived from passive/read-only telemetry."""

    id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str  # tls | headers | cookies | disclosure | transport | cors | cve | dns | html ...
    title: str
    evidence: str
    remediation: str
    cwe: str | None = None
    asvs: str | None = None
    owasp: str | None = None
    nist: str | None = None


@dataclass(frozen=True)
class PostureScore:
    """Overall defensive posture grade, domain breakdown, and finding counts."""

    score: int
    grade: str  # A | B | C | D | F
    risk_level: str  # MINIMAL | LOW | MODERATE | HIGH | CRITICAL
    counts: dict[str, int] = field(default_factory=dict)
    category_scores: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RemediationSnippet:
    """Single copy-pasteable defensive hardening snippet addressing specific finding IDs."""

    title: str
    stack: str
    finding_ids: list[str]
    language: str
    config: str


@dataclass(frozen=True)
class RemediationPlan:
    """Canonical output envelope for offline deterministic remediation playbooks."""

    target: str
    detected_stacks: list[str]
    selected_stack: str
    snippets: list[RemediationSnippet] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "remediation_plan"


@dataclass(frozen=True)
class AssessmentResult:
    """Canonical output envelope for `s1shell assess`."""

    target: str
    url: str
    pinned_ip: str
    scope_id: str
    auth_ref: str
    posture: PostureScore
    findings: list[AssessmentFinding]
    profile: ProfileResult
    fingerprint: FingerprintResult
    cve: CVESearchResult | None = None
    ai_analysis: AIAnalysisResult | None = None
    preset: str = "web"
    suppressed_findings: list[AssessmentFinding] = field(default_factory=list)
    remediation_snippets: list[RemediationSnippet] = field(default_factory=list)
    saved_files: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "assess_report"


@dataclass(frozen=True)
class BatchTargetSummary:
    """Summary of one target inside a sequential guarded batch assessment."""

    target: str
    status: str  # ok | blocked_out_of_scope | blocked_unauthorized | error
    exit_code: int
    url: str | None = None
    score: int | None = None
    grade: str | None = None
    risk_level: str | None = None
    highest_severity: str | None = None
    finding_count: int = 0
    cve_count: int = 0
    error: str | None = None


@dataclass(frozen=True)
class BatchAssessmentResult:
    """Consolidated summary of sequential guarded `assess --targets-file` execution."""

    targets_total: int
    succeeded: int
    blocked: int
    errored: int
    average_score: float | None
    results: list[BatchTargetSummary] = field(default_factory=list)
    saved_files: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "batch_assess_report"


@dataclass(frozen=True)
class AssessmentDiffResult:
    """Posture drift comparison between a baseline and current assessment artifact."""

    baseline_path: str
    current_path: str
    baseline_url: str
    current_url: str
    score_before: int
    score_after: int
    score_delta: int
    grade_before: str
    grade_after: str
    risk_before: str
    risk_after: str
    cert_days_delta: int | None = None
    new_findings: list[dict[str, str]] = field(default_factory=list)
    resolved_findings: list[dict[str, str]] = field(default_factory=list)
    persisting_count: int = 0
    new_cves: list[str] = field(default_factory=list)
    resolved_cves: list[str] = field(default_factory=list)
    stack_added: list[str] = field(default_factory=list)
    stack_removed: list[str] = field(default_factory=list)
    regressed: bool = False
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "assess_diff_report"
