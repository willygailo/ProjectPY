"""Offline unit and CLI tests for the defensive AI module and `.env` helpers."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import httpx
import pytest

from s1shell.ai.service import AIService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch, main
from s1shell.config import (
    DEFAULT_ANTHROPIC_MODEL,
    RuntimeConfig,
    classify_anthropic_key,
    mask_api_key,
    parse_dotenv,
)
from s1shell.doctor import run_doctor
from s1shell.errors import NetworkError, ValidationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_dotenv_helpers_and_config_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)

    parsed = parse_dotenv(
        """
        # Comment line
        ANTHROPIC_API_KEY="sk-ant-api03-examplekey1234"
        export ANTHROPIC_MODEL='claude-sonnet-4-20250514'
        EMPTY_LINE=
        PLAIN=hello
        """
    )
    assert parsed["ANTHROPIC_API_KEY"] == "sk-ant-api03-examplekey1234"
    assert parsed["ANTHROPIC_MODEL"] == "claude-sonnet-4-20250514"
    assert parsed["PLAIN"] == "hello"

    assert mask_api_key("short") == "***"
    assert mask_api_key("sk-ant-api03-abcdef1234") == "sk-ant-api...1234"

    assert classify_anthropic_key(None) == "unset"
    assert classify_anthropic_key("  ") == "unset"
    assert classify_anthropic_key("sk-ant-admin01-xyz") == "admin"
    assert classify_anthropic_key("sk-ant-api03-xyz") == "standard"
    assert classify_anthropic_key("custom-token") == "custom"

    home = tmp_path / ".s1shell"
    home.mkdir(parents=True)
    home_env = home / ".env"
    home_env.write_text('ANTHROPIC_API_KEY="sk-ant-api03-homekey0001"\n', encoding="utf-8")

    proj_env = tmp_path / "project.env"
    proj_env.write_text('ANTHROPIC_API_KEY="sk-ant-api03-projkey0002"\n', encoding="utf-8")

    cfg = RuntimeConfig(
        home_dir=home,
        scope_file=home / "scope.yaml",
        audit_log=home / "audit.log",
        cache_db=home / "cache.db",
        env_file=home_env,
        project_env_file=proj_env,
    )
    key, src = cfg.get_anthropic_api_key()
    assert key == "sk-ant-api03-projkey0002"
    assert src == str(proj_env)
    assert cfg.get_anthropic_model() == DEFAULT_ANTHROPIC_MODEL

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-envoverride")
    key2, src2 = cfg.get_anthropic_api_key()
    assert key2 == "sk-ant-api03-envoverride"
    assert src2 == "environment"

    isolated = RuntimeConfig.from_env(home_override=home)
    assert isolated.project_env_file is None


def test_cli_ai_env_lifecycle_and_formats(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    home = tmp_path / ".s1shell"

    # Initially unset
    out = io.StringIO()
    code = main(
        ["--home", str(home), "ai", "env", "--format", "json"],
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == 0
    status = json.loads(out.getvalue())
    assert status["artifact_type"] == "ai_env_report"
    assert status["configured"] is False
    assert status["key_type"] == "unset"
    assert status["masked_key"] is None

    # Save a standard key via CLI
    std_key = "sk-ant-api03-testsecretvalue9876"
    out = io.StringIO()
    code = main(
        [
            "--home",
            str(home),
            "ai",
            "env",
            "--set-key",
            std_key,
            "--model",
            "claude-sonnet-4-20250514",
            "--format",
            "json",
        ],
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == 0
    saved = json.loads(out.getvalue())
    assert saved["configured"] is True
    assert saved["key_type"] == "standard"
    assert saved["masked_key"] == "sk-ant-api...9876"
    assert std_key not in out.getvalue()

    env_path = home / ".env"
    assert env_path.exists()
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

    # Verify table and md rendering never expose the raw secret
    for fmt in ("table", "md"):
        fmt_out = io.StringIO()
        code = main(
            ["--home", str(home), "--no-color", "ai", "env", "--format", fmt],
            stdout=fmt_out,
            stderr=io.StringIO(),
        )
        assert code == 0
        assert "sk-ant-api...9876" in fmt_out.getvalue()
        assert std_key not in fmt_out.getvalue()

    # Save an admin key and confirm admin warning classification
    admin_key = "sk-ant-admin01-adminsecretvalue1234"
    out = io.StringIO()
    code = main(
        ["--home", str(home), "ai", "env", "--set-key", admin_key, "--format", "json"],
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == 0
    admin_status = json.loads(out.getvalue())
    assert admin_status["key_type"] == "admin"
    assert "Admin key" in admin_status["note"]
    assert admin_key not in out.getvalue()


def test_doctor_anthropic_key_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    home = tmp_path / ".s1shell"
    cfg = RuntimeConfig.from_env(home_override=home)

    # Unset -> ok
    rep_unset = run_doctor(cfg)
    ant_chk = next(c for c in rep_unset.checks if c.name == "anthropic_api_key")
    assert ant_chk.status == "ok"
    assert "not set" in ant_chk.detail
    assert rep_unset.healthy is True

    # Standard key -> ok
    home.mkdir(parents=True, exist_ok=True)
    cfg.env_file.write_text('ANTHROPIC_API_KEY="sk-ant-api03-stdkey9999"\n', encoding="utf-8")
    rep_std = run_doctor(cfg)
    ant_std = next(c for c in rep_std.checks if c.name == "anthropic_api_key")
    assert ant_std.status == "ok"
    assert "sk-ant-api...9999" in ant_std.detail

    # Admin key -> warn (still healthy)
    cfg.env_file.write_text('ANTHROPIC_API_KEY="sk-ant-admin01-admkey8888"\n', encoding="utf-8")
    rep_adm = run_doctor(cfg)
    ant_adm = next(c for c in rep_adm.checks if c.name == "anthropic_api_key")
    assert ant_adm.status == "warn"
    assert "Admin key" in ant_adm.detail
    assert rep_adm.healthy is True


def test_ai_analyze_with_mock_transport_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    home = tmp_path / ".s1shell"
    home.mkdir(parents=True, exist_ok=True)
    (home / ".env").write_text('ANTHROPIC_API_KEY="sk-ant-api03-validtest5555"\n', encoding="utf-8")
    cfg = RuntimeConfig.from_env(home_override=home)

    captured_requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(
            {
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": json.loads(request.content.decode("utf-8")),
            }
        )
        return httpx.Response(
            200,
            json={
                "id": "msg_01",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Enable HSTS and restrict Server banners."}],
                "usage": {"input_tokens": 120, "output_tokens": 25},
            },
        )

    audit_log = AuditLogger(cfg.audit_log)
    svc = AIService(cfg, audit_logger=audit_log, transport=httpx.MockTransport(handler))
    parser = build_parser()

    for fmt in ("json", "md", "table"):
        args = parser.parse_args(
            [
                "--home",
                str(home),
                "--no-color",
                "--format",
                fmt,
                "ai",
                "analyze",
                "--input",
                str(FIXTURES / "sample_profile.json"),
                "--prompt",
                "Summarize defensive header gaps.",
            ]
        )
        out = io.StringIO()
        code = dispatch(args, ai_service=svc, stdout=out, stderr=io.StringIO())
        assert code == 0
        text = out.getvalue()
        assert "Enable HSTS" in text
        if fmt == "json":
            parsed = json.loads(text)
            assert parsed["artifact_type"] == "ai_analysis_report"
            assert parsed["input_tokens"] == 120
            assert parsed["output_tokens"] == 25

    assert len(captured_requests) == 3
    first = captured_requests[0]
    headers = first["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "sk-ant-api03-validtest5555"
    assert headers["anthropic-version"] == "2023-06-01"
    body = first["body"]
    assert isinstance(body, dict)
    assert "defensive" in str(body["system"]).lower()
    assert "Summarize defensive header gaps." in str(body["messages"])
    assert "app.example.com" in str(body["messages"])

    events = audit_log.read_recent(limit=10)
    assert len(events) == 3
    assert all(e.category == "intel" for e in events)
    assert all(e.command == "ai analyze" for e in events)
    assert all(e.target == "api.anthropic.com" for e in events)
    assert all(e.outcome == "success" for e in events)


def test_ai_analyze_error_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    home = tmp_path / ".s1shell"

    # Empty input and prompt -> exit 1
    err = io.StringIO()
    assert main(["--home", str(home), "ai", "analyze"], stdout=io.StringIO(), stderr=err) == 1
    assert "Provide at least one" in err.getvalue()

    # Missing API key -> exit 1
    err = io.StringIO()
    assert (
        main(
            ["--home", str(home), "ai", "analyze", "--prompt", "Review headers"],
            stdout=io.StringIO(),
            stderr=err,
        )
        == 1
    )
    assert "ANTHROPIC_API_KEY is not configured" in err.getvalue()

    # Admin key rejected with 401 -> NetworkError mentioning Admin keys + audit log error
    home.mkdir(parents=True, exist_ok=True)
    (home / ".env").write_text('ANTHROPIC_API_KEY="sk-ant-admin01-admtest0000"\n', encoding="utf-8")
    cfg = RuntimeConfig.from_env(home_override=home)

    def unauth_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"type": "error", "error": {"type": "authentication_error", "message": "invalid"}},
        )

    audit_log = AuditLogger(cfg.audit_log)
    svc = AIService(cfg, audit_logger=audit_log, transport=httpx.MockTransport(unauth_handler))
    with pytest.raises(NetworkError, match="Admin keys"):
        svc.analyze(prompt="Check posture")

    events = audit_log.read_recent(limit=5)
    assert events[-1].outcome == "error"
    assert events[-1].exit_code == 1

    # Invalid JSON artifact -> ValidationError
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid JSON"):
        svc.analyze(inputs=[bad_json])
