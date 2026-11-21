"""AI module service: `.env`, skills, distillation, pipelines, grounding, ReAct & chat."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

import httpx

from s1shell.ai.client import AIClientProtocol, build_ai_client, build_system_prompt
from s1shell.ai.distill import distill_artifact
from s1shell.ai.guardrails import wrap_untrusted_telemetry
from s1shell.ai.investigate import ReadOnlyToolExecutor, run_readonly_investigation
from s1shell.ai.models import (
    AIAnalysisResult,
    AIEnvStatus,
    AIInvestigationResult,
    AIPipelineStageResult,
)
from s1shell.ai.pipelines import (
    STRUCTURED_OUTPUT_INSTRUCTIONS,
    get_pipeline_stages,
    parse_structured_json,
)
from s1shell.ai.redact import TelemetryRedactor
from s1shell.ai.skills import (
    AISkill,
    AISkillsCatalog,
    build_skill_prompt_addendum,
    get_skill,
    load_skills,
)
from s1shell.ai.verify import extract_known_references, verify_analysis_grounding
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import (
    SUPPORTED_AI_PROVIDERS,
    RuntimeConfig,
    atomic_write_private,
    classify_anthropic_key,
    load_dotenv_file,
    mask_api_key,
)
from s1shell.cve.cache import CVECache
from s1shell.errors import ExitCode, NetworkError, ValidationError

_MAX_ARTIFACT_CHARS = 16_000
_TELEMETRY_NONCE_RE = re.compile(r'id="t_[0-9a-f]+"')

_PROVIDER_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai_compat": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "ollama": "OLLAMA_API_KEY",
    "builtin": "BUILTIN_API_KEY",
}

_PROVIDER_MODEL_VARS = {
    "anthropic": "ANTHROPIC_MODEL",
    "openai_compat": "OPENAI_MODEL",
    "gemini": "GEMINI_MODEL",
    "ollama": "OLLAMA_MODEL",
    "builtin": "BUILTIN_MODEL",
}


def _build_env_note(
    provider: str,
    configured: bool,
    key_type: str,
    *,
    workspace_id: str | None = None,
) -> str:
    if provider == "builtin":
        return (
            "Built-in offline tactical & defensive synthesizer active "
            "(zero cloud API key or network required)."
        )
    if provider == "ollama":
        return (
            "Local Ollama provider active (no cloud API key required; keeps telemetry air-gapped)."
        )
    if not configured:
        env_var = _PROVIDER_KEY_VARS.get(provider, "ANTHROPIC_API_KEY")
        return f"{env_var} not configured. Set it in .env or via `s1shell ai env --set-key`."
    if provider == "anthropic" and key_type == "admin":
        return (
            "Admin key (sk-ant-admin*) detected; /v1/messages inference requires a "
            "standard sk-ant-api* key or sk-ant-usr* key + ANTHROPIC_WORKSPACE_ID "
            "(auto-fallback to builtin tactical synthesizer active)."
        )
    if provider == "anthropic" and key_type == "user" and not workspace_id:
        return (
            "User-scoped key (sk-ant-usr*) detected without ANTHROPIC_WORKSPACE_ID; "
            "set `--workspace-id wrkspc_...` so requests include `anthropic-workspace-id`."
        )
    return f"{provider} API key configured and ready for defensive analysis."


def _format_dotenv(values: dict[str, str]) -> str:
    lines: list[str] = []
    for key, val in values.items():
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + ("\n" if lines else "")


def _ai_cache_key(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "ai_resp_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _expand_input_paths(inputs: list[Path]) -> list[Path]:
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
                cand = resolved / name
                if cand.is_file():
                    expanded.append(cand)
            if not expanded:
                for p in sorted(resolved.glob("*.json"))[:6]:
                    if p.is_file():
                        expanded.append(p)
        else:
            expanded.append(path)
    return expanded


class AIService:
    """Manages `.env`, skills, distillation, pipelines, grounding, ReAct investigation, & chat."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        audit_logger: AuditLogger | None = None,
        cache: CVECache | None = None,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        self._audit = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self._cache = cache
        self._transport = transport
        self._sleeper = sleeper

    @property
    def cache(self) -> CVECache:
        """Lazily initialize local SQLite cache for optional AI response caching."""
        if self._cache is None:
            self._cache = CVECache(self._cfg.cache_db)
        return self._cache

    def list_skills(self) -> AISkillsCatalog:
        """Return all bundled and custom (`~/.s1shell/skills.d/*.yaml`) defensive AI skills."""
        skills = load_skills(extra_dir=self._cfg.skills_dir)
        custom_count = sum(1 for s in skills if s.source != "bundled")
        return AISkillsCatalog(skills=skills, custom_count=custom_count)

    def get_skill(self, skill_id: str) -> AISkill:
        """Retrieve a single defensive AI skill definition by ID."""
        return get_skill(skill_id, extra_dir=self._cfg.skills_dir)

    def env_status(self, *, provider: str | None = None) -> AIEnvStatus:
        """Inspect current AI provider, API key, endpoint, and model configuration safely."""
        active_prov = (provider or self._cfg.get_ai_provider()).strip().lower()
        if active_prov not in SUPPORTED_AI_PROVIDERS:
            raise ValidationError(
                f"Unsupported AI provider '{active_prov}'. "
                f"Choose {', '.join(SUPPORTED_AI_PROVIDERS)}."
            )
        api_key, source = self._cfg.get_ai_api_key(active_prov)
        if active_prov == "anthropic":
            key_type = classify_anthropic_key(api_key)
        elif active_prov in {"ollama", "builtin"}:
            key_type = "local"
        else:
            key_type = "standard" if api_key else "unset"

        configured = True if active_prov in {"ollama", "builtin"} else bool(api_key)
        masked = mask_api_key(api_key) if api_key else None
        model = self._cfg.get_ai_model(active_prov)
        base_url = self._cfg.get_ai_base_url(active_prov)
        workspace_id = (
            self._cfg.get_anthropic_workspace_id()[0] if active_prov == "anthropic" else None
        )
        env_file = (
            source
            if source not in ("environment", "unset", "builtin")
            else str(
                self._cfg.project_env_file
                if self._cfg.project_env_file is not None and self._cfg.project_env_file.is_file()
                else self._cfg.env_file
            )
        )
        return AIEnvStatus(
            configured=configured,
            masked_key=masked,
            key_type=key_type,
            source=source if active_prov not in {"ollama", "builtin"} else "local",
            model=model,
            env_file=env_file,
            note=_build_env_note(active_prov, configured, key_type, workspace_id=workspace_id),
            provider=active_prov,
            base_url=base_url,
            workspace_id=workspace_id,
        )

    def save_env(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        workspace_id: str | None = None,
        env_file: Path | None = None,
    ) -> AIEnvStatus:
        """Persist AI provider, key, workspace ID, endpoint, and/or model to `0600` `.env`."""
        clean_key = api_key.strip() if api_key is not None else None
        clean_model = model.strip() if model is not None else None
        clean_prov = provider.strip().lower() if provider is not None else None
        clean_url = base_url.strip() if base_url is not None else None
        clean_ws = workspace_id.strip() if workspace_id is not None else None

        if api_key is not None and not clean_key:
            raise ValidationError("--set-key cannot be empty.")
        if model is not None and not clean_model:
            raise ValidationError("--model cannot be empty.")
        if clean_prov is not None and clean_prov not in SUPPORTED_AI_PROVIDERS:
            raise ValidationError(
                f"Unsupported AI provider '{provider}'. Choose {', '.join(SUPPORTED_AI_PROVIDERS)}."
            )
        if base_url is not None and not clean_url:
            raise ValidationError("--base-url cannot be empty.")
        if workspace_id is not None and not clean_ws:
            raise ValidationError("--workspace-id cannot be empty.")
        if (
            clean_key is None
            and clean_model is None
            and clean_prov is None
            and clean_url is None
            and clean_ws is None
        ):
            raise ValidationError(
                "Provide --set-key, --model, --provider, --workspace-id, and/or --base-url "
                "to update `.env`."
            )

        target_path = (
            env_file.expanduser().resolve() if env_file is not None else self._cfg.env_file
        )
        existing = load_dotenv_file(target_path)
        active_prov = (
            clean_prov
            or existing.get("S1SHELL_AI_PROVIDER", "").strip().lower()
            or self._cfg.get_ai_provider()
        )
        if active_prov not in SUPPORTED_AI_PROVIDERS:
            active_prov = "anthropic"

        if clean_prov is not None:
            existing["S1SHELL_AI_PROVIDER"] = clean_prov
        if clean_url is not None:
            existing["S1SHELL_AI_BASE_URL"] = clean_url
        if clean_key is not None:
            existing[_PROVIDER_KEY_VARS[active_prov]] = clean_key
        if clean_model is not None:
            existing[_PROVIDER_MODEL_VARS[active_prov]] = clean_model
        if clean_ws is not None:
            existing["ANTHROPIC_WORKSPACE_ID"] = clean_ws

        atomic_write_private(
            target_path,
            _format_dotenv(existing),
            private_parent=(target_path.parent == self._cfg.home_dir),
        )

        if env_file is not None:
            saved_key = existing.get(_PROVIDER_KEY_VARS[active_prov], "").strip() or None
            if active_prov == "anthropic":
                key_type = classify_anthropic_key(saved_key)
            elif active_prov in {"ollama", "builtin"}:
                key_type = "local"
            else:
                key_type = "standard" if saved_key else "unset"
            configured = True if active_prov in {"ollama", "builtin"} else bool(saved_key)
            saved_model = existing.get(
                _PROVIDER_MODEL_VARS[active_prov], ""
            ).strip() or self._cfg.get_ai_model(active_prov)
            saved_url = existing.get(
                "S1SHELL_AI_BASE_URL", ""
            ).strip() or self._cfg.get_ai_base_url(active_prov)
            saved_ws = (
                existing.get("ANTHROPIC_WORKSPACE_ID", "").strip() or None
                if active_prov == "anthropic"
                else None
            )
            return AIEnvStatus(
                configured=configured,
                masked_key=mask_api_key(saved_key) if saved_key else None,
                key_type=key_type,
                source=str(target_path),
                model=saved_model,
                env_file=str(target_path),
                note=_build_env_note(active_prov, configured, key_type, workspace_id=saved_ws),
                provider=active_prov,
                base_url=saved_url,
                workspace_id=saved_ws,
            )
        return self.env_status(provider=active_prov)

    def _prepare_artifact_bundle(
        self,
        *,
        inputs: list[Path],
        redact: bool,
        compact: bool,
    ) -> tuple[list[Path], list[Any], list[str], TelemetryRedactor | None, list[str]]:
        artifact_paths = _expand_input_paths(inputs)
        redactor = TelemetryRedactor() if redact else None
        raw_objects: list[Any] = []
        blocks: list[str] = []
        injection_warnings: list[str] = []

        for path in artifact_paths:
            try:
                raw_text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise ValidationError(f"Failed to read artifact '{path}': {exc}") from exc
            try:
                parsed = json.loads(raw_text)
            except ValueError as exc:
                raise ValidationError(f"Invalid JSON in artifact '{path}': {exc}") from exc

            raw_objects.append(parsed)
            processed = distill_artifact(parsed, max_chars=12_000) if compact else parsed
            if redactor is not None:
                processed = redactor.redact_artifact(processed)

            pretty = json.dumps(processed, indent=2)
            if len(pretty) > _MAX_ARTIFACT_CHARS:
                compact_json = json.dumps(processed, separators=(",", ":"))
                if len(compact_json) <= _MAX_ARTIFACT_CHARS:
                    pretty = compact_json
                else:
                    pretty = pretty[:_MAX_ARTIFACT_CHARS] + "\n... [truncated]"

            wrapped, warns = wrap_untrusted_telemetry(pretty, source=path.name)
            injection_warnings.extend(warns)
            blocks.append(f"### Artifact: {path.name}\n{wrapped}")

        return artifact_paths, raw_objects, blocks, redactor, injection_warnings

    def prepare_context(
        self,
        *,
        inputs: list[Path],
        skill: str | None = None,
        mode: str = "triage",
        redact: bool = True,
        compact: bool = True,
        prompt: str | None = None,
    ) -> dict[str, Any]:
        """Build an offline distilled, redacted, guardrail-wrapped prompt bundle (no LLM calls)."""
        skill_obj = self.get_skill(skill) if skill else None
        skill_addendum = build_skill_prompt_addendum(skill_obj) if skill_obj is not None else None
        system_prompt = build_system_prompt(mode, skill_addendum=skill_addendum)

        artifact_paths, raw_objects, blocks, redactor, inj_warnings = self._prepare_artifact_bundle(
            inputs=inputs,
            redact=redact,
            compact=compact,
        )
        default_task = (
            skill_obj.user_template
            if (skill_obj is not None and skill_obj.user_template)
            else "Triage the provided S1shell artifacts and recommend prioritized defensive steps."
        )
        task_text = prompt.strip() if prompt and prompt.strip() else default_task
        eff_task = redactor.redact_text(task_text) if redactor is not None else task_text
        user_parts = [f"Operator request:\n{eff_task}"]
        if blocks:
            user_parts.append("S1shell JSON artifacts:\n\n" + "\n\n".join(blocks))

        return {
            "artifact_type": "ai_prepared_context",
            "skill": skill_obj.id if skill_obj else None,
            "mode": mode.strip().lower(),
            "redacted": redact,
            "redactions_applied": redactor.replacement_count if redactor is not None else 0,
            "compact": compact,
            "input_artifacts": [str(p) for p in artifact_paths],
            "known_references": sorted(extract_known_references(raw_objects)),
            "injection_warnings": inj_warnings,
            "system_prompt": system_prompt,
            "user_prompt": "\n\n".join(user_parts),
        }

    def _resolve_active_client(
        self,
        *,
        provider: str | None,
        model: str | None,
        base_url: str | None,
        local_only: bool,
        fallback_provider: str | None = None,
    ) -> tuple[AIClientProtocol, str, str, str | None]:
        """Resolve AI client, auto-falling back to `builtin` on an `sk-ant-admin*` key."""
        active_prov = (provider or self._cfg.get_ai_provider()).strip().lower()
        api_key, _ = self._cfg.get_ai_api_key(active_prov)
        preflight_fallback: str | None = None

        if (
            active_prov == "anthropic"
            and classify_anthropic_key(api_key) == "admin"
            and self._transport is None
            and not local_only
            and not fallback_provider
        ):
            active_prov = "builtin"
            api_key = None
            preflight_fallback = "builtin"

        client = build_ai_client(
            self._cfg,
            provider=active_prov,
            api_key=api_key,
            base_url=base_url if preflight_fallback is None else None,
            local_only=local_only,
            transport=self._transport,
            sleeper=self._sleeper,
        )
        chosen_model = (
            model.strip()
            if (model and model.strip() and preflight_fallback is None)
            else self._cfg.get_ai_model(active_prov)
        )
        return client, active_prov, chosen_model, preflight_fallback

    def _complete_with_fallback(
        self,
        *,
        primary_client: AIClientProtocol,
        primary_provider: str,
        primary_model: str,
        fallback_provider: str | None,
        local_only: bool,
        prompt: str,
        max_tokens: int,
        system_prompt: str,
    ) -> tuple[str, int, int, str, str, str | None]:
        started = time.monotonic()
        try:
            text, in_tok, out_tok = primary_client.complete(
                prompt=prompt,
                model=primary_model,
                max_tokens=max_tokens,
                system_prompt=system_prompt,
            )
            self._log_intel("ai analyze", primary_client.audit_target, "success", 0, started)
            return text, in_tok, out_tok, primary_provider, primary_model, None
        except NetworkError as primary_exc:
            self._log_intel(
                "ai analyze",
                primary_client.audit_target,
                "error",
                int(ExitCode.ERROR),
                started,
                error=str(primary_exc),
            )
            auto_fb = (
                "builtin" if (self._transport is None and primary_provider != "builtin") else None
            )
            effective_fb = (
                fallback_provider.strip().lower()
                if (fallback_provider and fallback_provider.strip())
                else auto_fb
            )
            if not effective_fb or effective_fb == primary_provider:
                raise
            fb_prov = effective_fb
            fb_key, _ = self._cfg.get_ai_api_key(fb_prov)
            fb_client = build_ai_client(
                self._cfg,
                provider=fb_prov,
                api_key=fb_key,
                local_only=local_only,
                transport=self._transport,
                sleeper=self._sleeper,
            )
            fb_model = self._cfg.get_ai_model(fb_prov)
            fb_started = time.monotonic()
            try:
                text, in_tok, out_tok = fb_client.complete(
                    prompt=prompt,
                    model=fb_model,
                    max_tokens=max_tokens,
                    system_prompt=system_prompt,
                )
                self._log_intel("ai analyze", fb_client.audit_target, "success", 0, fb_started)
                return text, in_tok, out_tok, fb_prov, fb_model, fb_prov
            except Exception as fb_exc:
                self._log_intel(
                    "ai analyze",
                    fb_client.audit_target,
                    "error",
                    int(ExitCode.ERROR),
                    fb_started,
                    error=str(fb_exc),
                )
                raise
        except Exception as exc:
            self._log_intel(
                "ai analyze",
                primary_client.audit_target,
                "error",
                int(ExitCode.ERROR),
                started,
                error=str(exc),
            )
            raise

    def analyze(
        self,
        *,
        inputs: list[Path] | None = None,
        prompt: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        mode: str = "triage",
        skill: str | None = None,
        pipeline: str | None = None,
        structured: bool = False,
        redact: bool = False,
        restore: bool = False,
        compact: bool = True,
        local_only: bool = False,
        fallback_provider: str | None = None,
        use_cache: bool = False,
        refresh_cache: bool = False,
        max_tokens: int = 1024,
    ) -> AIAnalysisResult:
        """Run defensive AI analysis with skills, pipelines, guardrails, grounding, & redaction."""
        raw_inputs = list(inputs or [])
        clean_prompt = prompt.strip() if prompt else ""
        if not raw_inputs and not clean_prompt:
            raise ValidationError("Provide at least one --input artifact or --prompt.")
        if max_tokens <= 0:
            raise ValidationError("--max-tokens must be a positive integer.")

        skill_obj = self.get_skill(skill) if skill else None
        skill_addendum = build_skill_prompt_addendum(skill_obj) if skill_obj is not None else None
        system_prompt = build_system_prompt(mode, skill_addendum=skill_addendum)
        if structured:
            system_prompt = f"{system_prompt}\n\n{STRUCTURED_OUTPUT_INSTRUCTIONS}"

        client, active_prov, chosen_model, preflight_fb = self._resolve_active_client(
            provider=provider,
            model=model,
            base_url=base_url,
            local_only=local_only,
            fallback_provider=fallback_provider,
        )

        artifact_paths, raw_objects, artifact_blocks, redactor, injection_warnings = (
            self._prepare_artifact_bundle(
                inputs=raw_inputs,
                redact=redact,
                compact=compact,
            )
        )
        known_refs = extract_known_references(raw_objects)

        default_task = (
            skill_obj.user_template
            if (skill_obj is not None and skill_obj.user_template)
            else "Triage the provided S1shell artifacts and recommend prioritized defensive steps."
        )
        task_text = clean_prompt if clean_prompt else default_task
        effective_task = redactor.redact_text(task_text) if redactor is not None else task_text
        prompt_parts = [f"Operator request:\n{effective_task}"]
        if artifact_blocks:
            prompt_parts.append("S1shell JSON artifacts:\n\n" + "\n\n".join(artifact_blocks))
        full_prompt = "\n\n".join(prompt_parts)

        # Optional SQLite response cache (only for single-shot non-pipeline runs)
        cache_k: str | None = None
        if use_cache and not pipeline:
            cache_k = _ai_cache_key(
                {
                    "provider": active_prov,
                    "model": chosen_model,
                    "mode": mode.strip().lower(),
                    "skill": skill_obj.id if skill_obj else None,
                    "structured": structured,
                    "system": system_prompt,
                    "prompt": _TELEMETRY_NONCE_RE.sub('id="t_NONCE"', full_prompt),
                }
            )
            if not refresh_cache:
                cached_val = self.cache.get(cache_k, ttl_seconds=self._cfg.cve_cache_ttl_seconds)
                if isinstance(cached_val, dict) and isinstance(cached_val.get("analysis"), str):
                    analysis_text = cached_val["analysis"]
                    restored_flag = False
                    if redactor is not None and restore:
                        analysis_text = redactor.restore_text(analysis_text)
                        restored_flag = True
                    cached_struct = parse_structured_json(analysis_text) if structured else None
                    grounding = (
                        verify_analysis_grounding(analysis_text, known_refs)
                        if raw_objects
                        else None
                    )
                    return AIAnalysisResult(
                        model=chosen_model,
                        task=task_text,
                        input_artifacts=[str(p) for p in artifact_paths],
                        analysis=analysis_text,
                        input_tokens=int(cached_val.get("input_tokens", 0) or 0),
                        output_tokens=int(cached_val.get("output_tokens", 0) or 0),
                        provider=active_prov,
                        mode=mode.strip().lower(),
                        redacted=redact,
                        skill=skill_obj.id if skill_obj else None,
                        structured_data=cached_struct,
                        redactions_applied=redactor.replacement_count if redactor else 0,
                        restored=restored_flag,
                        cached=True,
                        injection_warnings=injection_warnings,
                        grounding=grounding,
                    )

        pipeline_stages: list[AIPipelineStageResult] = []
        used_prov = active_prov
        used_model = chosen_model
        fallback_used: str | None = preflight_fb
        in_tok = 0
        out_tok = 0

        if pipeline:
            stages = get_pipeline_stages(pipeline)
            prior_outputs: list[str] = []
            analysis_text = ""
            for idx, stage in enumerate(stages):
                stage_sys = f"{system_prompt}\n\nPipeline role ({stage.role}): {stage.instruction}"
                stage_prompt = full_prompt
                if prior_outputs:
                    stage_prompt += "\n\nPrior Verified Stage Outputs:\n\n" + "\n\n---\n\n".join(
                        prior_outputs
                    )
                if structured and idx == len(stages) - 1:
                    stage_sys = f"{stage_sys}\n\n{STRUCTURED_OUTPUT_INSTRUCTIONS}"

                s_text, s_in, s_out, used_prov, used_model, fb_used = self._complete_with_fallback(
                    primary_client=client,
                    primary_provider=active_prov,
                    primary_model=chosen_model,
                    fallback_provider=fallback_provider,
                    local_only=local_only,
                    prompt=stage_prompt,
                    max_tokens=max_tokens,
                    system_prompt=stage_sys,
                )
                if fb_used:
                    fallback_used = fb_used
                in_tok += s_in
                out_tok += s_out
                analysis_text = s_text
                prior_outputs.append(f"### {stage.name} ({stage.role})\n{s_text}")
                pipeline_stages.append(
                    AIPipelineStageResult(
                        stage=stage.name,
                        role=stage.role,
                        input_tokens=s_in,
                        output_tokens=s_out,
                        preview=s_text[:200],
                    )
                )
        else:
            analysis_text, in_tok, out_tok, used_prov, used_model, fb_used = (
                self._complete_with_fallback(
                    primary_client=client,
                    primary_provider=active_prov,
                    primary_model=chosen_model,
                    fallback_provider=fallback_provider,
                    local_only=local_only,
                    prompt=full_prompt,
                    max_tokens=max_tokens,
                    system_prompt=system_prompt,
                )
            )
            if fb_used:
                fallback_used = fb_used

        # Structured JSON validation + single automatic repair retry if malformed
        struct_data: dict[str, Any] | None = None
        if structured:
            struct_data = parse_structured_json(analysis_text)
            if struct_data is None:
                repair_prompt = (
                    "Your previous reply did not match the required JSON schema. "
                    "Convert the following content into a single strictly valid JSON object "
                    "matching the schema without adding new Finding or CVE IDs:\n\n"
                    f"{analysis_text[:4000]}"
                )
                rep_text, r_in, r_out, used_prov, used_model, fb_used = (
                    self._complete_with_fallback(
                        primary_client=client,
                        primary_provider=active_prov,
                        primary_model=chosen_model,
                        fallback_provider=fallback_provider,
                        local_only=local_only,
                        prompt=repair_prompt,
                        max_tokens=max_tokens,
                        system_prompt=system_prompt,
                    )
                )
                if fb_used:
                    fallback_used = fb_used
                in_tok += r_in
                out_tok += r_out
                rep_parsed = parse_structured_json(rep_text)
                if rep_parsed is not None:
                    analysis_text = rep_text
                    struct_data = rep_parsed

        if cache_k is not None:
            self.cache.set(
                cache_k,
                {
                    "analysis": analysis_text,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                },
            )

        restored_flag = False
        if redactor is not None and restore:
            analysis_text = redactor.restore_text(analysis_text)
            if struct_data is not None:
                struct_data = parse_structured_json(analysis_text) or struct_data
            restored_flag = True

        grounding = verify_analysis_grounding(analysis_text, known_refs) if raw_objects else None

        return AIAnalysisResult(
            model=used_model,
            task=task_text,
            input_artifacts=[str(p) for p in artifact_paths],
            analysis=analysis_text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            provider=used_prov,
            mode=mode.strip().lower(),
            redacted=redact,
            skill=skill_obj.id if skill_obj else None,
            pipeline=pipeline.strip().lower() if pipeline else None,
            pipeline_stages=pipeline_stages,
            structured_data=struct_data,
            redactions_applied=redactor.replacement_count if redactor else 0,
            restored=restored_flag,
            cached=False,
            fallback_used=fallback_used,
            injection_warnings=injection_warnings,
            grounding=grounding,
        )

    def investigate(
        self,
        *,
        inputs: list[Path],
        goal: str,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        max_steps: int = 5,
        max_tokens: int = 1200,
        redact: bool = False,
        restore: bool = False,
        local_only: bool = False,
        tool_executor: ReadOnlyToolExecutor | None = None,
        custom_tool_runner: Callable[[str, dict[str, Any]], tuple[str, Any]] | None = None,
    ) -> AIInvestigationResult:
        """Run a bounded read-only ReAct investigation over artifacts & offline/passive tools."""
        client, active_prov, chosen_model, _ = self._resolve_active_client(
            provider=provider,
            model=model,
            base_url=base_url,
            local_only=local_only,
        )
        executor = (
            tool_executor
            if tool_executor is not None
            else ReadOnlyToolExecutor(self._cfg, audit_logger=self._audit)
        )
        return run_readonly_investigation(
            client=client,
            executor=executor,
            audit_logger=self._audit,
            provider=active_prov,
            model=chosen_model,
            goal=goal,
            inputs=inputs,
            max_steps=max_steps,
            max_tokens=max_tokens,
            redact=redact,
            restore=restore,
            custom_tool_runner=custom_tool_runner,
        )

    def chat(
        self,
        *,
        inputs: list[Path] | None = None,
        skill: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        redact: bool = False,
        restore: bool = False,
        local_only: bool = False,
        max_tokens: int = 1024,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> int:
        """Interactive multi-turn defensive copilot over saved engagement artifacts."""
        in_stream = stdin if stdin is not None else sys.stdin
        out_stream = stdout if stdout is not None else sys.stdout

        client, active_prov, chosen_model, _ = self._resolve_active_client(
            provider=provider,
            model=model,
            base_url=base_url,
            local_only=local_only,
        )

        active_skill: AISkill | None = self.get_skill(skill) if skill else None
        active_redact = redact
        artifact_paths, raw_objects, artifact_blocks, redactor, inj_warnings = (
            self._prepare_artifact_bundle(
                inputs=list(inputs or []),
                redact=active_redact,
                compact=True,
            )
        )
        known_refs = extract_known_references(raw_objects)
        history: list[tuple[str, str]] = []

        out_stream.write(
            f"S1shell AI Copilot ({active_prov}/{chosen_model}) | "
            f"artifacts={len(artifact_paths)} | redact={active_redact} | "
            f"skill={active_skill.id if active_skill else 'none'}\n"
            "Commands: /skill <id>, /skills, /verify, /save <file.md>, /exit\n"
        )
        if inj_warnings:
            out_stream.write(
                f"[Warning] Prompt-injection patterns neutralized: {len(inj_warnings)}\n"
            )
        out_stream.flush()

        for raw_line in in_stream:
            line = raw_line.strip()
            if not line:
                continue
            if line in {"/exit", "/quit"}:
                break
            if line == "/skills":
                cat = self.list_skills()
                out_stream.write("Available skills: " + ", ".join(s.id for s in cat.skills) + "\n")
                out_stream.flush()
                continue
            if line.startswith("/skill "):
                sid = line.split(None, 1)[1].strip()
                try:
                    active_skill = self.get_skill(sid)
                    out_stream.write(f"Switched skill -> {active_skill.id} ({active_skill.name})\n")
                except ValidationError as exc:
                    out_stream.write(f"Error: {exc}\n")
                out_stream.flush()
                continue
            if line == "/verify":
                if not history:
                    out_stream.write("No assistant reply yet to verify.\n")
                else:
                    rep = verify_analysis_grounding(history[-1][1], known_refs)
                    out_stream.write(f"Grounding: score={rep.grounding_score} | {rep.note}\n")
                out_stream.flush()
                continue
            if line.startswith("/save "):
                save_path = Path(line.split(None, 1)[1].strip()).expanduser().resolve()
                md_lines = [f"# S1shell AI Copilot Transcript ({active_prov}/{chosen_model})", ""]
                for u_msg, a_msg in history:
                    md_lines.extend([f"## Operator\n\n{u_msg}", "", f"## Assistant\n\n{a_msg}", ""])
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_text("\n".join(md_lines), encoding="utf-8")
                out_stream.write(f"Saved transcript to {save_path}\n")
                out_stream.flush()
                continue

            sys_prompt = build_system_prompt(
                "triage",
                skill_addendum=(
                    build_skill_prompt_addendum(active_skill) if active_skill is not None else None
                ),
            )
            eff_q = redactor.redact_text(line) if redactor is not None else line
            prompt_blocks: list[str] = []
            if artifact_blocks:
                prompt_blocks.append("Engagement telemetry:\n" + "\n\n".join(artifact_blocks))
            if history:
                hist_txt = "\n\n".join(f"User: {u}\nAssistant: {a[:1200]}" for u, a in history[-4:])
                prompt_blocks.append(f"Recent conversation:\n{hist_txt}")
            prompt_blocks.append(f"Operator question:\n{eff_q}")

            started = time.monotonic()
            reply, _, _ = client.complete(
                prompt="\n\n".join(prompt_blocks),
                model=chosen_model,
                max_tokens=max_tokens,
                system_prompt=sys_prompt,
            )
            self._log_intel("ai chat", client.audit_target, "success", 0, started)
            if redactor is not None and restore:
                reply = redactor.restore_text(reply)
            history.append((line, reply))
            out_stream.write(f"\n{reply}\n\n")
            out_stream.flush()

        return int(ExitCode.SUCCESS)

    def _log_intel(
        self,
        command: str,
        target: str,
        outcome: str,
        exit_code: int,
        started: float,
        *,
        error: str | None = None,
    ) -> None:
        self._audit.log(
            AuditEvent.create(
                category="intel",
                command=command,
                target=target,
                authorized_via="n/a",
                outcome=outcome,
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=error,
            )
        )
