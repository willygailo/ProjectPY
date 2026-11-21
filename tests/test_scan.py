"""Offline unit & CLI integration tests for `s1shell scan` (secrets, config, sbom)."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
from pathlib import Path

from s1shell.cli import main
from s1shell.cve.audit_deps import parse_dependency_file
from s1shell.errors import ExitCode
from s1shell.report.sarif import render_config_scan_sarif, render_secret_scan_sarif
from s1shell.scan.config import scan_config
from s1shell.scan.sbom import generate_cyclonedx_sbom
from s1shell.scan.secrets import scan_secrets


def test_secret_scanner_detects_redacts_and_ignores_placeholders(tmp_path: Path) -> None:
    aws_key = "AKIA" + "IOSFODNN7REALKY1"
    gh_tok = "ghp_" + "9xK2mP7vQ4nL8wR3tY6bC1zF5dH0jS2kU4a"
    stripe_key = "sk_live_" + "51H9xK2mP7vQ4nL8wR3tY6bC1z"
    db_uri = "postgresql://admin:Sup3rS3cretP@ss99@db.internal:5432/prod"
    ignored_key = "AKIA" + "IOSFODNN7IGNORD2"

    sample = tmp_path / "app.py"
    sample.write_text(
        "\n".join(
            [
                f'AWS = "{aws_key}"',
                f'GH = "{gh_tok}"',
                f'STRIPE = "{stripe_key}"',
                f'DB = "{db_uri}"',
                'PLACEHOLDER = "AKIAEXAMPLE000000000"',
                'ENV_REF = "${AWS_SECRET_ACCESS_KEY}"',
                f'SUPPRESSED = "{ignored_key}"  # s1shell:ignore',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Ignored via .gitignore
    (tmp_path / ".gitignore").write_text("ignored.env\n", encoding="utf-8")
    (tmp_path / "ignored.env").write_text(f"AWS={aws_key}\n", encoding="utf-8")

    # Binary file skipped cleanly
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02" + aws_key.encode("ascii"))

    res = scan_secrets(tmp_path)
    rule_ids = {f.rule_id for f in res.findings}
    assert {"SEC-AWS-001", "SEC-GH-001", "SEC-PAY-001", "SEC-DB-001"} <= rule_ids
    assert res.suppressed_count == 1
    assert res.highest_severity == "CRITICAL"

    # Raw secrets must never leak into serialized output or SARIF
    sarif_text = render_secret_scan_sarif(res)
    for raw_secret in (aws_key, gh_tok, stripe_key, "Sup3rS3cretP@ss99", ignored_key):
        assert raw_secret not in sarif_text
        for f in res.findings:
            assert raw_secret not in f.match_redacted
            assert raw_secret not in f.context_line

    sarif_obj = json.loads(sarif_text)
    assert sarif_obj["version"] == "2.1.0"
    loc = sarif_obj["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] >= 1
    assert loc["region"]["startColumn"] >= 1


def test_secret_scanner_git_staged_mode(tmp_path: Path) -> None:
    git_bin = shutil.which("git") or "/usr/bin/git"
    subprocess.run([git_bin, "init"], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        [git_bin, "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        [git_bin, "config", "user.name", "Test"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    leaked = "sk-ant-api03-" + "x9K2mP7vQ4nL8wR3tY6bC1zF5dH0jS2kU4a"
    (tmp_path / "staged.txt").write_text(f"key={leaked}\n", encoding="utf-8")
    subprocess.run(  # noqa: S603
        [git_bin, "add", "staged.txt"], cwd=tmp_path, check=True, capture_output=True
    )

    res = scan_secrets(tmp_path, git_staged=True)
    assert res.scan_mode == "git-staged"
    assert any(f.rule_id == "SEC-AI-001" and f.line == 1 for f in res.findings)
    assert leaked not in res.findings[0].match_redacted


def test_config_scanner_audits_docker_k8s_gha_compose_nginx_sshd_env(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:latest\n"
        "ENV API_SECRET=supersecret\n"
        "ADD https://example.com/setup.sh /tmp/\n"
        "RUN curl -fsSL https://example.com/install.sh | bash && chmod 777 /tmp\n",
        encoding="utf-8",
    )

    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      hostNetwork: true\n"
        "      volumes:\n"
        "        - name: dock\n"
        "          hostPath:\n"
        "            path: /var/run/docker.sock\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: nginx:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            capabilities:\n"
        "              add: ['SYS_ADMIN']\n",
        encoding="utf-8",
    )

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: pull_request_target\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        '      - run: echo "${{ github.event.issue.title }}"\n',
        encoding="utf-8",
    )

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:16\n"
        "    privileged: true\n"
        "    ports:\n"
        '      - "5432:5432"\n',
        encoding="utf-8",
    )

    (tmp_path / "nginx.conf").write_text(
        "server {\n  ssl_protocols TLSv1 TLSv1.2;\n  autoindex on;\n  proxy_ssl_verify off;\n}\n",
        encoding="utf-8",
    )

    (tmp_path / ".env.prod").write_text(
        "DEBUG=True\nNODE_TLS_REJECT_UNAUTHORIZED=0\n",
        encoding="utf-8",
    )
    (tmp_path / "sshd_config").write_text(
        "PermitRootLogin yes\nPermitEmptyPasswords yes\n",
        encoding="utf-8",
    )

    res = scan_config(tmp_path)
    ids = {f.rule_id for f in res.findings}
    expected = {
        "IAC-DOCK-001",
        "IAC-DOCK-002",
        "IAC-DOCK-003",
        "IAC-DOCK-004",
        "IAC-DOCK-005",
        "IAC-DOCK-006",
        "IAC-K8S-001",
        "IAC-K8S-002",
        "IAC-K8S-003",
        "IAC-K8S-006",
        "IAC-GHA-001",
        "IAC-GHA-002",
        "IAC-GHA-003",
        "IAC-GHA-004",
        "IAC-COMP-001",
        "IAC-COMP-004",
        "IAC-NGX-001",
        "IAC-NGX-002",
        "IAC-NGX-003",
        "IAC-NGX-004",
        "IAC-ENV-001",
        "IAC-ENV-002",
        "IAC-SSH-001",
        "IAC-SSH-003",
    }
    assert expected <= ids
    assert res.highest_severity == "CRITICAL"

    sarif = json.loads(render_config_scan_sarif(res))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(res.findings)


def test_sbom_generator_roundtrips_with_cve_audit_parser(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.3\nurllib3==2.2.2\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.19.2"}}),
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")

    res = generate_cyclonedx_sbom(tmp_path)
    assert res.bom_format == "CycloneDX"
    assert res.spec_version == "1.5"
    assert res.component_count == 4
    assert res.ecosystems == {"OCI": 1, "PyPI": 2, "npm": 1}

    sbom_file = tmp_path / "out.cdx.json"
    sbom_file.write_text(json.dumps(res.bom, indent=2), encoding="utf-8")
    fmt, parsed_pkgs = parse_dependency_file(sbom_file)
    assert fmt == "cyclonedx"
    assert {(p.ecosystem, p.name, p.version) for p in parsed_pkgs} == {
        ("PyPI", "requests", "2.32.3"),
        ("PyPI", "urllib3", "2.2.2"),
        ("npm", "express", "4.19.2"),
    }


def test_cli_scan_fail_on_policy_gate(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:latest\n", encoding="utf-8")
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        [
            "--home",
            str(tmp_path / ".home"),
            "scan",
            "config",
            str(tmp_path),
            "--fail-on",
            "HIGH",
            "--format",
            "json",
        ],
        stdout=out,
        stderr=err,
    )
    assert code == int(ExitCode.POLICY_FAILED)
    payload = json.loads(out.getvalue())
    assert payload["artifact_type"] == "config_scan_report"
    assert payload["highest_severity"] == "HIGH"
