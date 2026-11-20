"""End-to-end offline CLI tests covering exit codes, subcommands, and output formats."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

from s1shell.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_cli_scope_lifecycle_and_exit_codes(tmp_path: Path, monkeypatch: object) -> None:
    home = tmp_path / ".s1shell"
    out = io.StringIO()
    err = io.StringIO()

    # Empty scope -> profile exits with code 2
    code = main(
        ["--home", str(home), "profile", "https://example.com", "--authorized"],
        stdout=out,
        stderr=err,
    )
    assert code == 2

    # Add scope entry
    out = io.StringIO()
    code = main(
        [
            "--home",
            str(home),
            "scope",
            "add",
            "127.0.0.1",
            "--owner",
            "Local Lab",
            "--ref",
            "LAB-2026-01",
            "--expires",
            "2099-12-31",
            "--format",
            "json",
        ],
        stdout=out,
        stderr=err,
    )
    assert code == 0
    added = json.loads(out.getvalue())
    assert added["entries"][0]["target"] == "127.0.0.1"

    # scope check passes with exit 0
    out = io.StringIO()
    code = main(
        ["--home", str(home), "scope", "check", "https://127.0.0.1", "--format", "json"],
        stdout=out,
        stderr=err,
    )
    assert code == 0
    assert json.loads(out.getvalue())["in_scope"] is True

    # profile without --authorized in non-TTY exits with code 3
    monkeypatch_stdin = io.StringIO("")
    import s1shell.guard as guard_mod

    orig_stdin = guard_mod.sys.stdin
    try:
        guard_mod.sys.stdin = monkeypatch_stdin
        code = main(
            ["--home", str(home), "profile", "https://127.0.0.1"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == 3
    finally:
        guard_mod.sys.stdin = orig_stdin

    # audit list shows blocked attempts
    out = io.StringIO()
    code = main(
        ["--home", str(home), "audit", "list", "--format", "json"],
        stdout=out,
        stderr=err,
    )
    assert code == 0
    events = json.loads(out.getvalue())["events"]
    assert [e["exit_code"] for e in events] == [2, 3]


def test_cli_fingerprint_from_profile_and_report_build(tmp_path: Path) -> None:
    home = tmp_path / ".s1shell"
    fp_out = tmp_path / "fp.json"
    html_out = tmp_path / "report.html"

    code = main(
        [
            "--home",
            str(home),
            "fingerprint",
            "--from-profile",
            str(FIXTURES / "sample_profile.json"),
            "--format",
            "json",
            "--out",
            str(fp_out),
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0
    fp_data = json.loads(fp_out.read_text(encoding="utf-8"))
    assert fp_data["artifact_type"] == "fingerprint_report"

    code = main(
        [
            "--home",
            str(home),
            "--scope-file",
            str(FIXTURES / "sample_scope.yaml"),
            "report",
            "build",
            "--profile",
            str(FIXTURES / "sample_profile.json"),
            "--fingerprint",
            str(fp_out),
            "--operator",
            "Jane Doe",
            "--format",
            "html",
            "--out",
            str(html_out),
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0
    html = html_out.read_text(encoding="utf-8")
    assert "Jane Doe" in html
    assert "SOW-2026-014" in html


def test_cli_cve_cache_clear_and_module_entrypoint(tmp_path: Path) -> None:
    home = tmp_path / ".s1shell"
    out = io.StringIO()
    code = main(
        ["--home", str(home), "cve", "cache", "clear"],
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == 0
    assert "Cleared 0 cached CVE entries." in out.getvalue()

    proc = subprocess.run(
        [sys.executable, "-m", "s1shell", "--version"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        check=False,
    )
    assert proc.returncode == 0
    assert "s1shell 0.1.0" in proc.stdout


def test_cli_doctor_completion_audit_filters_and_format_validation(tmp_path: Path) -> None:
    home = tmp_path / ".s1shell"

    # doctor reports healthy state in JSON
    out = io.StringIO()
    code = main(
        ["--home", str(home), "doctor", "--format", "json"],
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == 0
    doc = json.loads(out.getvalue())
    assert doc["artifact_type"] == "doctor_report"
    assert doc["healthy"] is True

    # completion generates bash/zsh/fish scripts
    for shell in ("bash", "zsh", "fish"):
        comp_out = io.StringIO()
        code = main(["completion", shell], stdout=comp_out, stderr=io.StringIO())
        assert code == 0
        assert "s1shell" in comp_out.getvalue()

    # unsupported --format html on doctor fails cleanly with ExitCode.ERROR (1)
    err = io.StringIO()
    code = main(
        ["--home", str(home), "doctor", "--format", "html"],
        stdout=io.StringIO(),
        stderr=err,
    )
    assert code == 1
    assert "Unsupported format" in err.getvalue()

    # trigger one blocked audit record and query with filters + md format
    main(
        ["--home", str(home), "profile", "https://outside.example", "--authorized"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    md_out = io.StringIO()
    code = main(
        [
            "--home",
            str(home),
            "audit",
            "list",
            "--outcome",
            "blocked_out_of_scope",
            "--target",
            "outside",
            "--format",
            "md",
        ],
        stdout=md_out,
        stderr=io.StringIO(),
    )
    assert code == 0
    assert "blocked_out_of_scope" in md_out.getvalue()
    assert "outside.example" in md_out.getvalue()

    # doctor reports unhealthy (exit 1) when scope.yaml is invalid
    (home / "scope.yaml").write_text("not: [valid: yaml", encoding="utf-8")
    doc_tbl = io.StringIO()
    code = main(
        ["--home", str(home), "doctor", "--no-color"],
        stdout=doc_tbl,
        stderr=io.StringIO(),
    )
    assert code == 1
    assert "ERROR" in doc_tbl.getvalue()

    # profile table output renders protocol, headers, banners, and cookies via CLI dispatch
    from s1shell.cli import build_parser, dispatch
    from s1shell.profile.models import (
        BannerDisclosure,
        CookieFinding,
        DNSRecords,
        HeaderAnalysis,
        HeaderFinding,
        ProfileResult,
        ProtocolInfo,
        TLSResult,
    )

    class StubProfileService:
        def profile(
            self, target: str, *, authorized: bool = False, check_tls_versions: bool = False
        ) -> ProfileResult:
            return ProfileResult(
                target=target,
                url="https://example.com/",
                pinned_ip="93.184.216.34",
                scope_id="s1",
                auth_ref="REF-1",
                authorized_via="flag" if authorized else "interactive",
                dns=DNSRecords(a=["93.184.216.34"]),
                protocol=ProtocolInfo(status_code=200, http_version="HTTP/2", alpn_protocol="h2"),
                tls=TLSResult(
                    applicable=True,
                    negotiated_version="TLSv1.3",
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    verified=True,
                    issuer="CN=Test",
                    days_remaining=45,
                    supported_versions=["TLSv1.3"],
                ),
                headers=HeaderAnalysis(
                    security_headers=[
                        HeaderFinding(
                            header="Strict-Transport-Security",
                            present=True,
                            value="max-age=31536000",
                            status="ok",
                            note="HSTS configured.",
                        )
                    ],
                    banner_disclosures=[BannerDisclosure(header="Server", value="nginx/1.24.0")],
                    cookies=[
                        CookieFinding(name="sid", secure=True, http_only=True, same_site="Lax")
                    ],
                ),
            )

    parser = build_parser()
    parsed = parser.parse_args(
        ["--home", str(home), "--no-color", "profile", "https://example.com", "--authorized"]
    )
    prof_out = io.StringIO()
    assert (
        dispatch(
            parsed,
            profile_service=StubProfileService(),  # type: ignore[arg-type]
            stdout=prof_out,
            stderr=io.StringIO(),
        )
        == 0
    )
    rendered_tbl = prof_out.getvalue()
    assert "TLSv1.3" in rendered_tbl
    assert "Banner Disclosures" in rendered_tbl
    assert "Set-Cookie Attributes" in rendered_tbl
