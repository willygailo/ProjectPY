"""AI module service for `.env` management, redaction, and multi-provider defensive triage."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from s1shell.ai.client import build_ai_client, build_system_prompt
from s1shell.ai.models import AIAnalysisResult, AIEnvStatus
from s1shell.ai.redact import TelemetryRedactor
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import (
    SUPPORTED_AI_PROVIDERS,
    RuntimeConfig,
    chmod_private_file,
    classify_anthropic_key,
    ensure_private_dir,
    load_dotenv_file,
    mask_api_key,
)
from s1shell.errors import ExitCode, ValidationError

_MAX_ARTIFACT_CHARS = 16_000

_PROVIDER_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai_compat": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "ollama": "OLLAMA_API_KEY",
}

_PROVIDER_MODEL_VARS = {
    "anthropic": "ANTHROPIC_MODEL",
    "openai_compat": "OPENAI_MODEL",
    "gemini": "GEMINI_MODEL",
    "ollama": "OLLAMA_MODEL",
}


def _build_env_note(provider: str, configured: bool, key_type: str) -> str:
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
            "standard sk-ant-api* key."
        )
    return f"{provider} API key configured and ready for defensive analysis."


def _format_dotenv(values: dict[str, str]) -> str:
    lines: list[str] = []
    for key, val in values.items():
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + ("\n" if lines else "")


class AIService:
    """Manages `.env` credentials and multi-provider defensive AI triage workflows."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        audit_logger: AuditLogger | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        self._audit = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self._transport = transport

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
        elif active_prov == "ollama":
            key_type = "local"
        else:
            key_type = "standard" if api_key else "unset"

        configured = True if active_prov == "ollama" else bool(api_key)
        masked = mask_api_key(api_key) if api_key else None
        model = self._cfg.get_ai_model(active_prov)
        base_url = self._cfg.get_ai_base_url(active_prov)
        env_file = (
            source
            if source not in ("environment", "unset")
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
            source=source if active_prov != "ollama" else "local",
            model=model,
            env_file=env_file,
            note=_build_env_note(active_prov, configured, key_type),
            provider=active_prov,
            base_url=base_url,
        )

    def save_env(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        env_file: Path | None = None,
    ) -> AIEnvStatus:
        """Persist AI provider, key, endpoint, and/or model to a `0600` `.env` file."""
        clean_key = api_key.strip() if api_key is not None else None
        clean_model = model.strip() if model is not None else None
        clean_prov = provider.strip().lower() if provider is not None else None
        clean_url = base_url.strip() if base_url is not None else None

        if api_key is not None and not clean_key:
            raise ValidationError("--set-key cannot be empty.")
        if model is not None and not clean_model:
            raise ValidationError("--model cannot be empty.")
        if clean_prov is not None and clean_prov not in SUPPORTED_AI_PROVIDERS:
            raise ValidationError(
                f"Unsupported AI provider '{provider}'. "
                f"Choose {', '.join(SUPPORTED_AI_PROVIDERS)}."
            )
        if base_url is not None and not clean_url:
            raise ValidationError("--base-url cannot be empty.")
        if (
            clean_key is None
            and clean_model is None
            and clean_prov is None
            and clean_url is None
        ):
            raise ValidationError(
                "Provide --set-key, --model, --provider, and/or --base-url to update `.env`."
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

        if target_path.parent == self._cfg.home_dir:
            ensure_private_dir(target_path.parent)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)

        target_path.write_text(_format_dotenv(existing), encoding="utf-8")
        chmod_private_file(target_path)

        if env_file is not None:
            saved_key = existing.get(_PROVIDER_KEY_VARS[active_prov], "").strip() or None
            if active_prov == "anthropic":
                key_type = classify_anthropic_key(saved_key)
            elif active_prov == "ollama":
                key_type = "local"
            else:
                key_type = "standard" if saved_key else "unset"
            configured = True if active_prov == "ollama" else bool(saved_key)
            saved_model = (
                existing.get(_PROVIDER_MODEL_VARS[active_prov], "").strip()
                or self._cfg.get_ai_model(active_prov)
            )
            saved_url = (
                existing.get("S1SHELL_AI_BASE_URL", "").strip()
                or self._cfg.get_ai_base_url(active_prov)
            )
            return AIEnvStatus(
                configured=configured,
                masked_key=mask_api_key(saved_key) if saved_key else None,
                key_type=key_type,
                source=str(target_path),
                model=saved_model,
                env_file=str(target_path),
                note=_build_env_note(active_prov, configured, key_type),
                provider=active_prov,
                base_url=saved_url,
            )
        return self.env_status(provider=active_prov)

    def analyze(
        self,
        *,
        inputs: list[Path] | None = None,
        prompt: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        mode: str = "triage",
        redact: bool = False,
        max_tokens: int = 1024,
    ) -> AIAnalysisResult:
        """Run defensive AI analysis over saved S1shell JSON artifacts and/or a prompt."""
        artifact_paths = list(inputs or [])
        clean_prompt = prompt.strip() if prompt else ""
        if not artifact_paths and not clean_prompt:
            raise ValidationError("Provide at least one --input artifact or --prompt.")
        if max_tokens <= 0:
            raise ValidationError("--max-tokens must be a positive integer.")

        system_prompt = build_system_prompt(mode)
        active_prov = (provider or self._cfg.get_ai_provider()).strip().lower()
        api_key, _ = self._cfg.get_ai_api_key(active_prov)
        client = build_ai_client(
            self._cfg,
            provider=active_prov,
            api_key=api_key,
            base_url=base_url,
            transport=self._transport,
        )

        redactor = TelemetryRedactor() if redact else None
        artifact_blocks: list[str] = []
        for path in artifact_paths:
            try:
                raw_text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise ValidationError(f"Failed to read artifact '{path}': {exc}") from exc
            try:
                parsed = json.loads(raw_text)
            except ValueError as exc:
                raise ValidationError(f"Invalid JSON in artifact '{path}': {exc}") from exc

            if redactor is not None:
                parsed = redactor.redact_artifact(parsed)

            pretty = json.dumps(parsed, indent=2)
            if len(pretty) > _MAX_ARTIFACT_CHARS:
                pretty = pretty[:_MAX_ARTIFACT_CHARS] + "\n... [truncated]"
            artifact_blocks.append(
                f"### Artifact: {path.name}\n"
                f'<untrusted_telemetry source="{path.name}">\n'
                f"{pretty}\n"
                "</untrusted_telemetry>"
            )

        task_text = (
            clean_prompt
            if clean_prompt
            else "Triage the provided S1shell artifacts and recommend prioritized defensive steps."
        )
        effective_task = redactor.redact_text(task_text) if redactor is not None else task_text
        prompt_parts = [f"Operator request:\n{effective_task}"]
        if artifact_blocks:
            prompt_parts.append("S1shell JSON artifacts:\n\n" + "\n\n".join(artifact_blocks))
        full_prompt = "\n\n".join(prompt_parts)

        chosen_model = (
            model.strip()
            if model and model.strip()
            else self._cfg.get_ai_model(active_prov)
        )
        started = time.monotonic()

        try:
            analysis_text, in_tok, out_tok = client.complete(
                prompt=full_prompt,
                model=chosen_model,
                max_tokens=max_tokens,
                system_prompt=system_prompt,
            )
            self._log_intel("ai analyze", client.audit_target, "success", 0, started)
        except Exception as exc:
            self._log_intel(
                "ai analyze",
                client.audit_target,
                "error",
                int(ExitCode.ERROR),
                started,
                error=str(exc),
            )
            raise

        return AIAnalysisResult(
            model=chosen_model,
            task=task_text,
            input_artifacts=[str(p) for p in artifact_paths],
            analysis=analysis_text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            provider=active_prov,
            mode=mode.strip().lower(),
            redacted=redact,
        )

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
