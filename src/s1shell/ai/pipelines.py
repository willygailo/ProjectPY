"""Multi-stage defensive reasoning pipelines and structured JSON output schemas."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from s1shell.errors import ValidationError

SUPPORTED_AI_PIPELINES = ("deep-triage", "purple-team", "executive-pack")

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL | re.IGNORECASE)

STRUCTURED_OUTPUT_INSTRUCTIONS = (
    "Return ONLY a single valid JSON object (no markdown commentary outside JSON) matching this "
    "exact schema:\n"
    "{\n"
    '  "summary": "concise executive assessment paragraph",\n'
    '  "risk_rating": "CRITICAL | HIGH | MEDIUM | LOW",\n'
    '  "prioritized_actions": [\n'
    "    {\n"
    '      "priority": "P0 | P1 | P2 | P3",\n'
    '      "title": "short action title",\n'
    '      "finding_refs": ["HDR-HSTS", "CVE-2021-23017"],\n'
    '      "remediation": "concrete defensive fix",\n'
    '      "verification": "how to verify fix safely"\n'
    "    }\n"
    "  ],\n"
    '  "attack_paths": ["theoretical path grounded strictly in observed telemetry"],\n'
    '  "detection_ideas": ["defensive SIEM/WAF/logging check"],\n'
    '  "quick_wins": ["high-impact low-risk defensive win"]\n'
    "}\n"
    "Cite ONLY Finding IDs and CVE IDs that literally appear inside <untrusted_telemetry>."
)


@dataclass(frozen=True)
class PipelineStageSpec:
    """Single stage inside a multi-step defensive AI reasoning pipeline."""

    name: str
    role: str
    instruction: str


_PIPELINES: dict[str, tuple[PipelineStageSpec, ...]] = {
    "deep-triage": (
        PipelineStageSpec(
            name="evidence-extraction",
            role="Fact & Evidence Extractor",
            instruction=(
                "Stage 1 (Evidence Extraction): Extract a concise, bulleted inventory of confirmed "
                "findings (exact Finding IDs & severities), EOL software, KEV/EPSS CVEs, and OSINT "
                "anomalies strictly from <untrusted_telemetry>. Do not speculate or invent IDs."
            ),
        ),
        PipelineStageSpec(
            name="attack-path-prioritization",
            role="Attack-Path & Chokepoint Strategist",
            instruction=(
                "Stage 2 (Attack-Path & Chokepoint Analysis): Using Stage 1's verified facts, "
                "identify the highest-risk theoretical attack paths (MITRE ATT&CK / CWE) and the "
                "single-fix chokepoint controls that neutralize the most risk."
            ),
        ),
        PipelineStageSpec(
            name="precision-critique",
            role="Precision Auditor & Final Synthesizer",
            instruction=(
                "Stage 3 (Self-Critique & Final Defensive Plan): Audit Stage 2 against the raw "
                "telemetry, remove any unsupported claim or unverified ID, and produce the final "
                "prioritized defensive action plan with safe verification commands."
            ),
        ),
    ),
    "purple-team": (
        PipelineStageSpec(
            name="threat-modeling",
            role="Threat Modeler",
            instruction=(
                "Stage 1 (Threat Modeling): Map the confirmed findings, fingerprinted stack, and "
                "CVEs to theoretical adversary tactics (MITRE ATT&CK) and impact scenarios."
            ),
        ),
        PipelineStageSpec(
            name="hardening-and-detections",
            role="Blue-Team Hardening & Detection Engineer",
            instruction=(
                "Stage 2 (Hardening & Detection Engineering): Produce stack-specific defensive "
                "hardening configurations AND corresponding Sigma/SIEM/WAF detection rules to "
                "prevent and detect each threat scenario from Stage 1."
            ),
        ),
        PipelineStageSpec(
            name="executive-roadmap",
            role="Security Program Synthesizer",
            instruction=(
                "Stage 3 (Unified Purple-Team Deliverable): Combine Stages 1–2 into a clean final "
                "brief with (1) Top Threat Paths, (2) Preventive Hardening, (3) Detective Rules, "
                "and (4) 30/60/90-Day Rollout."
            ),
        ),
    ),
    "executive-pack": (
        PipelineStageSpec(
            name="technical-triage",
            role="Principal AppSec Analyst",
            instruction=(
                "Stage 1 (Technical Triage): Summarize the highest-priority technical risks, exact "
                "Finding/CVE IDs, and concrete engineering remediation workstreams."
            ),
        ),
        PipelineStageSpec(
            name="leadership-compliance-brief",
            role="CISO Advisor & Compliance Brief Writer",
            instruction=(
                "Stage 2 (Executive & Compliance Pack): Translate Stage 1 into an executive-ready "
                "summary covering business risk impact, OWASP/NIST/ISO compliance posture, and "
                "prioritized 30/60/90-day remediation milestones."
            ),
        ),
    ),
}


def get_pipeline_stages(name: str) -> tuple[PipelineStageSpec, ...]:
    """Return ordered stages for a named multi-step reasoning pipeline."""
    norm = name.strip().lower()
    if norm not in _PIPELINES:
        opts = ", ".join(SUPPORTED_AI_PIPELINES)
        raise ValidationError(f"Unsupported AI pipeline '{name}'. Choose {opts}.")
    return _PIPELINES[norm]


def parse_structured_json(text: str) -> dict[str, Any] | None:
    """Parse and validate a structured AI JSON response (tolerating fenced ```json blocks)."""
    cleaned = text.strip()
    candidate = cleaned
    fenced = _JSON_FENCE_RE.search(cleaned)
    if fenced:
        candidate = fenced.group(1).strip()
    else:
        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            candidate = cleaned[first_brace : last_brace + 1]

    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("summary"), str) or not parsed["summary"].strip():
        return None
    if not isinstance(parsed.get("prioritized_actions"), list):
        return None
    return parsed
