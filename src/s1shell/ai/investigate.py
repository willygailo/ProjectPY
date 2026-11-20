"""Bounded, strictly read-only ReAct AI investigator over offline/passive S1shell tools."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from s1shell.ai.client import DEFENSIVE_SYSTEM_PROMPT, AIClientProtocol
from s1shell.ai.distill import distill_artifact
from s1shell.ai.guardrails import wrap_untrusted_telemetry
from s1shell.ai.models import AIInvestigationResult, AIInvestigationStep
from s1shell.ai.redact import TelemetryRedactor
from s1shell.ai.verify import extract_known_references, verify_analysis_grounding
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.codec.service import CodecService
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService
from s1shell.cve.service import CVEService
from s1shell.errors import ExitCode, S1ShellError, ValidationError
from s1shell.fingerprint.service import FingerprintService
from s1shell.intel.service import IntelService
from s1shell.models import dumps_json

MAX_INVESTIGATION_STEPS = 8
_MAX_OBSERVATION_CHARS = 4_000
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL | re.IGNORECASE)

# Strictly offline / passive read-only tools — ZERO target-touching tools permitted.
READONLY_INVESTIGATION_TOOLS: dict[str, str] = {
    "cve_get": "Look up CVE IDs via NVD/CVE.org/GHSA (`cve_id` or `cve_ids`, `enrich`).",
    "cve_audit": "Audit a local lockfile/SBOM via OSV.dev (`file_path`, `recursive`, `enrich`).",
    "intel_lookup": "Passive VT/GreyNoise/urlscan/RDAP lookup (`indicator`, `sources`, `offline`).",
    "intel_ct": "Passive crt.sh Certificate Transparency lookup (`domain`, `offline`).",
    "intel_rdap": "Passive RDAP domain/IP registration lookup (`indicator`, `offline`).",
    "codec_inspect": "Offline JWT/X.509/hash/timestamp/auto-decode inspector (`text`).",
    "fingerprint_from_profile": "Offline tech fingerprinting from profile JSON (`profile_path`).",
    "assess_diff": "Offline baseline vs current assess diff (`baseline_path`, `current_path`).",
    "remediate": "Offline stack-tailored hardening snippets (`assess_path`, `stack`).",
}


def _parse_action_json(text: str) -> dict[str, Any] | None:
    cleaned = text.strip()
    candidate = cleaned
    fenced = _JSON_FENCE_RE.search(cleaned)
    if fenced:
        candidate = fenced.group(1).strip()
    else:
        first = cleaned.find("{")
        last = cleaned.rfind("}")
        if first != -1 and last > first:
            candidate = cleaned[first : last + 1]
    try:
        obj = json.loads(candidate)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _build_investigator_system_prompt() -> str:
    tools_desc = "\n".join(
        f"- `{name}`: {desc}" for name, desc in READONLY_INVESTIGATION_TOOLS.items()
    )
    return (
        f"{DEFENSIVE_SYSTEM_PROMPT}\n\n"
        "You are operating inside a bounded read-only defensive investigation loop. "
        "At each turn, respond with ONLY a valid JSON object using one of two schemas:\n"
        '1) Tool call: {"action": "tool", "thought": "why this read-only lookup helps", '
        '"tool": "<tool_name>", "arguments": { ... }}\n'
        '2) Final brief: {"action": "final", "thought": "why investigation is complete", '
        '"answer": "comprehensive defensive markdown brief citing exact Finding/CVE IDs"}\n\n'
        f"Allowed strictly read-only / passive tools:\n{tools_desc}\n\n"
        "Never attempt to call any tool outside this list. Never invent Finding or CVE IDs."
    )


def _expand_artifact_paths(inputs: list[Path]) -> list[Path]:
    expanded: list[Path] = []
    for path in inputs:
        resolved = path.expanduser().resolve()
        if resolved.is_dir():
            for name in (
                "assess.json",
                "profile.json",
                "fingerprint.json",
                "cves.json",
                "intel.json",
            ):
                candidate = resolved / name
                if candidate.is_file():
                    expanded.append(candidate)
            if not expanded:
                for p in sorted(resolved.glob("*.json"))[:6]:
                    if p.is_file():
                        expanded.append(p)
        elif resolved.is_file():
            expanded.append(resolved)
        else:
            raise ValidationError(f"Investigation input path does not exist: '{path}'.")
    return expanded


class ReadOnlyToolExecutor:
    """Executes strictly read-only offline/passive S1shell tools for AI investigations."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        audit_logger: AuditLogger,
        cve_service: CVEService | None = None,
        dep_audit_service: DependencyAuditService | None = None,
        intel_service: IntelService | None = None,
        fingerprint_service: FingerprintService | None = None,
        codec_service: CodecService | None = None,
    ) -> None:
        self.cfg = cfg
        self.audit_logger = audit_logger
        self.cve_service = (
            cve_service if cve_service is not None else CVEService(cfg, audit_logger=audit_logger)
        )
        self.dep_audit_service = (
            dep_audit_service
            if dep_audit_service is not None
            else DependencyAuditService(cfg, audit_logger=audit_logger)
        )
        self.intel_service = (
            intel_service
            if intel_service is not None
            else IntelService(cfg, audit_logger=audit_logger)
        )
        self.fingerprint_service = (
            fingerprint_service
            if fingerprint_service is not None
            else FingerprintService(cfg, audit_logger=audit_logger)
        )
        self.codec_service = codec_service if codec_service is not None else CodecService()

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, Any]:
        """Run one allowlisted read-only tool and return `(json_text, parsed_obj)`."""
        norm = tool_name.strip().lower()
        if norm not in READONLY_INVESTIGATION_TOOLS:
            raise ValidationError(
                f"Tool '{tool_name}' is not permitted in read-only investigation mode."
            )

        if norm == "cve_get":
            raw_ids = arguments.get("cve_ids")
            if isinstance(raw_ids, list) and raw_ids:
                res = self.cve_service.get_many(
                    [str(x) for x in raw_ids],
                    offline=bool(arguments.get("offline", False)),
                    enrich=bool(arguments.get("enrich", True)),
                )
            else:
                res = self.cve_service.get(
                    str(arguments.get("cve_id", "")),
                    offline=bool(arguments.get("offline", False)),
                    enrich=bool(arguments.get("enrich", True)),
                )
            text = dumps_json(res)
            return text, json.loads(text)

        if norm == "cve_audit":
            dep_res = self.dep_audit_service.audit_path(
                Path(str(arguments.get("file_path", ""))),
                recursive=bool(arguments.get("recursive", False)),
                offline=bool(arguments.get("offline", False)),
                enrich=bool(arguments.get("enrich", True)),
            )
            text = dumps_json(dep_res)
            return text, json.loads(text)

        if norm == "intel_lookup":
            raw_src = arguments.get("sources")
            src_list = [str(s) for s in raw_src] if isinstance(raw_src, list) else None
            intel_res = self.intel_service.lookup(
                str(arguments.get("indicator", "")),
                pinned_ip=arguments.get("pinned_ip"),
                sources=src_list,
                offline=bool(arguments.get("offline", False)),
            )
            text = dumps_json(intel_res)
            return text, json.loads(text)

        if norm == "intel_ct":
            ct_res = self.intel_service.ct_lookup(
                str(arguments.get("domain", "")),
                offline=bool(arguments.get("offline", False)),
            )
            text = dumps_json(ct_res)
            return text, json.loads(text)

        if norm == "intel_rdap":
            rdap_res = self.intel_service.rdap_lookup(
                str(arguments.get("indicator", "")),
                offline=bool(arguments.get("offline", False)),
            )
            text = dumps_json(rdap_res)
            return text, json.loads(text)

        if norm == "codec_inspect":
            ins_res = self.codec_service.inspect(str(arguments.get("text", "")).encode("utf-8"))
            text = dumps_json(ins_res)
            return text, json.loads(text)

        if norm == "fingerprint_from_profile":
            fp_res = self.fingerprint_service.from_profile(
                Path(str(arguments.get("profile_path", "")))
            )
            text = dumps_json(fp_res)
            return text, json.loads(text)

        if norm == "assess_diff":
            from s1shell.assess.diff import diff_assessments

            diff_res = diff_assessments(
                Path(str(arguments.get("baseline_path", ""))),
                Path(str(arguments.get("current_path", ""))),
            )
            text = dumps_json(diff_res)
            return text, json.loads(text)

        if norm == "remediate":
            from s1shell.assess.remediate import generate_remediation_from_file

            rem_res = generate_remediation_from_file(
                Path(str(arguments.get("assess_path", ""))),
                stack=str(arguments.get("stack") or "auto"),
            )
            text = dumps_json(rem_res)
            return text, json.loads(text)

        raise ValidationError(f"Unsupported read-only tool '{tool_name}'.")


def run_readonly_investigation(
    *,
    client: AIClientProtocol,
    executor: ReadOnlyToolExecutor,
    audit_logger: AuditLogger,
    provider: str,
    model: str,
    goal: str,
    inputs: list[Path],
    max_steps: int = 5,
    max_tokens: int = 1200,
    redact: bool = False,
    restore: bool = False,
    custom_tool_runner: Callable[[str, dict[str, Any]], tuple[str, Any]] | None = None,
) -> AIInvestigationResult:
    """Execute a bounded read-only ReAct investigation over artifacts and passive tools."""
    clean_goal = goal.strip()
    if not clean_goal:
        raise ValidationError("--goal must not be empty for `ai investigate`.")
    if max_steps < 1 or max_steps > MAX_INVESTIGATION_STEPS:
        raise ValidationError(f"--max-steps must be between 1 and {MAX_INVESTIGATION_STEPS}.")

    artifact_paths = _expand_artifact_paths(inputs)
    redactor = TelemetryRedactor() if redact else None
    parsed_artifacts: list[Any] = []
    injection_warnings: list[str] = []
    context_blocks: list[str] = []

    for path in artifact_paths:
        try:
            raw_obj = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(f"Failed to parse artifact '{path}': {exc}") from exc
        parsed_artifacts.append(raw_obj)
        distilled = distill_artifact(raw_obj, max_chars=8_000)
        if redactor is not None:
            distilled = redactor.redact_artifact(distilled)
        pretty = json.dumps(distilled, indent=2)
        if len(pretty) > 8_000:
            pretty = pretty[:8_000] + "\n... [truncated]"
        wrapped, warns = wrap_untrusted_telemetry(pretty, source=path.name)
        injection_warnings.extend(warns)
        context_blocks.append(f"### Artifact: {path.name}\n{wrapped}")

    system_prompt = _build_investigator_system_prompt()
    effective_goal = redactor.redact_text(clean_goal) if redactor is not None else clean_goal
    transcript_parts: list[str] = [f"Investigation Goal:\n{effective_goal}"]
    if context_blocks:
        transcript_parts.append("Initial Engagement Telemetry:\n\n" + "\n\n".join(context_blocks))

    steps: list[AIInvestigationStep] = []
    total_in = 0
    total_out = 0
    final_answer = ""
    run_tool = custom_tool_runner if custom_tool_runner is not None else executor.execute

    for step_idx in range(1, max_steps + 1):
        started = time.monotonic()
        prompt_text = "\n\n".join(transcript_parts) + (
            f"\n\nStep {step_idx}/{max_steps}: Return your next JSON action "
            '(choose "final" if you have enough evidence).'
        )
        try:
            raw_reply, in_tok, out_tok = client.complete(
                prompt=prompt_text,
                model=model,
                max_tokens=max_tokens,
                system_prompt=system_prompt,
            )
            total_in += in_tok
            total_out += out_tok
            audit_logger.log(
                AuditEvent.create(
                    category="intel",
                    command="ai investigate",
                    target=client.audit_target,
                    authorized_via="n/a",
                    outcome="success",
                    exit_code=int(ExitCode.SUCCESS),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
        except Exception as exc:
            audit_logger.log(
                AuditEvent.create(
                    category="intel",
                    command="ai investigate",
                    target=client.audit_target,
                    authorized_via="n/a",
                    outcome="error",
                    exit_code=int(ExitCode.ERROR),
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error=str(exc),
                )
            )
            raise

        action_obj = _parse_action_json(raw_reply)
        if action_obj is None:
            final_answer = raw_reply
            steps.append(
                AIInvestigationStep(
                    step=step_idx,
                    thought="Model returned direct narrative answer.",
                    observation_preview=raw_reply[:240],
                )
            )
            break

        action = str(action_obj.get("action") or "").strip().lower()
        thought = str(action_obj.get("thought") or "").strip()

        if action == "final" or step_idx == max_steps:
            ans = str(action_obj.get("answer") or raw_reply).strip()
            final_answer = ans
            steps.append(
                AIInvestigationStep(
                    step=step_idx,
                    thought=thought or "Concluded investigation.",
                    observation_preview=ans[:240],
                )
            )
            break

        if action == "tool":
            tool_name = str(action_obj.get("tool") or "").strip()
            raw_args = action_obj.get("arguments")
            tool_args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
            # Restore redacted args locally before invoking local read-only tool
            if redactor is not None:
                tool_args = {
                    k: (redactor.restore_text(v) if isinstance(v, str) else v)
                    for k, v in tool_args.items()
                }
            try:
                obs_text, obs_obj = run_tool(tool_name, tool_args)
                parsed_artifacts.append(obs_obj)
                distilled_obs = distill_artifact(obs_obj, max_chars=_MAX_OBSERVATION_CHARS)
                if redactor is not None:
                    distilled_obs = redactor.redact_artifact(distilled_obs)
                obs_pretty = json.dumps(distilled_obs, indent=2)
                if len(obs_pretty) > _MAX_OBSERVATION_CHARS:
                    obs_pretty = obs_pretty[:_MAX_OBSERVATION_CHARS] + "\n... [truncated]"
                wrapped_obs, obs_warns = wrap_untrusted_telemetry(
                    obs_pretty, source=f"tool:{tool_name}"
                )
                injection_warnings.extend(obs_warns)
                steps.append(
                    AIInvestigationStep(
                        step=step_idx,
                        thought=thought,
                        tool=tool_name,
                        arguments=tool_args if not redact else {},
                        observation_preview=obs_text[:240],
                    )
                )
                transcript_parts.append(
                    f"Step {step_idx} Tool `{tool_name}` Observation:\n{wrapped_obs}"
                )
            except (S1ShellError, ValueError, OSError) as exc:
                steps.append(
                    AIInvestigationStep(
                        step=step_idx,
                        thought=thought,
                        tool=tool_name,
                        arguments=tool_args if not redact else {},
                        error=str(exc),
                    )
                )
                transcript_parts.append(f"Step {step_idx} Tool `{tool_name}` Error: {exc}")
            continue

        final_answer = raw_reply
        steps.append(AIInvestigationStep(step=step_idx, thought=thought or "Finished."))
        break

    restored_applied = False
    if redactor is not None and restore:
        final_answer = redactor.restore_text(final_answer)
        restored_applied = True

    known_refs = extract_known_references(parsed_artifacts)
    grounding = verify_analysis_grounding(final_answer, known_refs)

    return AIInvestigationResult(
        model=model,
        provider=provider,
        goal=clean_goal,
        input_artifacts=[str(p) for p in artifact_paths],
        final_answer=final_answer,
        steps=steps,
        input_tokens=total_in,
        output_tokens=total_out,
        redacted=redact,
        restored=restored_applied,
        redactions_applied=redactor.replacement_count if redactor is not None else 0,
        injection_warnings=injection_warnings,
        grounding=grounding,
    )
