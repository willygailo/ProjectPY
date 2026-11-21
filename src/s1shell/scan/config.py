"""Offline IaC & DevOps security misconfiguration auditor (Docker, K8s, GHA, NGINX, SSH, .env)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from s1shell.errors import ValidationError
from s1shell.scan.models import ConfigFinding, ConfigScanResult

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "target",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)
_IGNORE_RE = re.compile(r"s1shell:ignore", re.IGNORECASE)

_DOCK_SECRET_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api_key|apikey|private_key|access_key)"
)
_CURL_PIPE_SH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_GHA_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"issue\.(?:title|body)|"
    r"pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|"
    r"comment\.body|"
    r"review\.body|"
    r"review_comment\.body|"
    r"discussion\.(?:title|body)|"
    r"pages\[\d*\]\.page_name|"
    r"commits\[[^\]]*\]\.(?:message|author\.name|author\.email)|"
    r"head_commit\.(?:message|author\.name|author\.email)"
    r")\s*\}\}"
)
_SHA40_RE = re.compile(r"@[0-9a-fA-F]{40}$")
_SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/var/run/docker.sock",
    "/run/containerd",
    "/var/lib/kubelet",
)
_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE"}
_DB_PORTS = {"5432", "3306", "27017", "6379", "9200", "5672", "11211", "1433"}


def _line_ignored(lines: list[str], line_no: int) -> bool:
    if 1 <= line_no <= len(lines) and _IGNORE_RE.search(lines[line_no - 1]):
        return True
    return bool(2 <= line_no <= len(lines) and _IGNORE_RE.search(lines[line_no - 2]))


def _find_line(lines: list[str], needle: str, *, start: int = 1) -> int:
    low = needle.lower()
    for idx in range(max(1, start), len(lines) + 1):
        if low in lines[idx - 1].lower():
            return idx
    return 1


def _audit_dockerfile(rel_path: str, text: str) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0
    has_non_root_user = False
    has_healthcheck = False
    last_from_line = 1

    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        upper = stripped.upper()

        if upper.startswith("FROM "):
            last_from_line = idx
            has_non_root_user = False
            image_part = stripped.split()[1] if len(stripped.split()) > 1 else ""
            if (
                image_part.lower() != "scratch"
                and "@sha256:" not in image_part
                and (":" not in image_part or image_part.endswith(":latest"))
            ):
                if _line_ignored(lines, idx):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-DOCK-002",
                            title="Dockerfile base image is unpinned or uses `:latest`",
                            severity="MEDIUM",
                            category="dockerfile",
                            file_path=rel_path,
                            line=idx,
                            evidence=stripped[:140],
                            remediation=(
                                "Pin the base image to an explicit version tag or "
                                "immutable `@sha256:` digest."
                            ),
                            fix_snippet=(
                                f"FROM {image_part.split(':', 1)[0]}:<version>@sha256:<digest>"
                            ),
                            cwe="CWE-829",
                            owasp="A08:2021",
                            nist="CM-2",
                        )
                    )
        elif upper.startswith("USER "):
            user_val = stripped.split()[1].lower() if len(stripped.split()) > 1 else ""
            if user_val not in {"root", "0", "0:0"}:
                has_non_root_user = True
        elif upper.startswith("HEALTHCHECK "):
            has_healthcheck = True
        elif upper.startswith("ADD "):
            parts = stripped.split()
            if any(p.startswith(("http://", "https://")) for p in parts[1:]):
                if _line_ignored(lines, idx):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-DOCK-004",
                            title="Dockerfile `ADD` fetches unverified remote URL",
                            severity="MEDIUM",
                            category="dockerfile",
                            file_path=rel_path,
                            line=idx,
                            evidence=stripped[:140],
                            remediation=(
                                "Use `COPY` for local files or `curl -fsSL` with SHA-256 checksum "
                                "verification."
                            ),
                            cwe="CWE-494",
                            owasp="A08:2021",
                            nist="SI-7",
                        )
                    )
        elif upper.startswith(("ENV ", "ARG ")) and _DOCK_SECRET_KEY_RE.search(stripped):
            if "=" in stripped or len(stripped.split()) >= 3:
                if _line_ignored(lines, idx):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-DOCK-005",
                            title="Potential secret passed via Dockerfile `ENV`/`ARG`",
                            severity="HIGH",
                            category="dockerfile",
                            file_path=rel_path,
                            line=idx,
                            evidence=stripped.split("=", 1)[0][:80] + "=***",
                            remediation=(
                                "Use BuildKit secret mounts (`RUN --mount=type=secret,...`) "
                                "instead of ENV/ARG."
                            ),
                            cwe="CWE-798",
                            owasp="A02:2021",
                            nist="IA-5",
                        )
                    )

        if _CURL_PIPE_SH_RE.search(stripped):
            if _line_ignored(lines, idx):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-DOCK-003",
                        title="Dockerfile pipes remote script directly into shell",
                        severity="HIGH",
                        category="dockerfile",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped[:140],
                        remediation=(
                            "Download artifacts, verify cryptographic SHA-256/GPG signatures, then "
                            "execute."
                        ),
                        cwe="CWE-494",
                        owasp="A08:2021",
                        nist="SI-7",
                    )
                )
        if re.search(r"\bchmod\s+(?:-R\s+)?0?777\b", stripped):
            if _line_ignored(lines, idx):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-DOCK-006",
                        title="World-writable permissions (`chmod 777`) in Dockerfile",
                        severity="MEDIUM",
                        category="dockerfile",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped[:140],
                        remediation=(
                            "Apply least-privilege permissions (e.g. `0750` or `0644`) owned by a "
                            "non-root UID."
                        ),
                        cwe="CWE-732",
                        owasp="A01:2021",
                        nist="AC-6",
                    )
                )
        if re.search(r"\b(?:openssh-server|sshd)\b", stripped) and upper.startswith("RUN "):
            if _line_ignored(lines, idx):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-DOCK-008",
                        title="SSH server installed inside container image",
                        severity="MEDIUM",
                        category="dockerfile",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped[:140],
                        remediation=(
                            "Remove SSH daemons from container images and use `docker/kubectl "
                            "exec`."
                        ),
                        cwe="CWE-250",
                        owasp="A05:2021",
                        nist="CM-7",
                    )
                )

    if not has_non_root_user:
        if _line_ignored(lines, last_from_line):
            suppressed += 1
        else:
            findings.append(
                ConfigFinding(
                    rule_id="IAC-DOCK-001",
                    title="Container runs as `root` (missing non-root `USER` directive)",
                    severity="HIGH",
                    category="dockerfile",
                    file_path=rel_path,
                    line=last_from_line,
                    evidence="Final build stage has no non-root USER instruction.",
                    remediation=(
                        "Create and switch to a dedicated unprivileged user before ENTRYPOINT/CMD."
                    ),
                    fix_snippet="RUN useradd --system --uid 10001 appuser\nUSER 10001",
                    cwe="CWE-250",
                    owasp="A05:2021",
                    nist="AC-6",
                )
            )
    if not has_healthcheck:
        findings.append(
            ConfigFinding(
                rule_id="IAC-DOCK-007",
                title="Dockerfile omits `HEALTHCHECK` instruction",
                severity="LOW",
                category="dockerfile",
                file_path=rel_path,
                line=last_from_line,
                evidence="No HEALTHCHECK directive found.",
                remediation=(
                    "Add a `HEALTHCHECK` instruction (or orchestrator liveness/readiness probes)."
                ),
                fix_snippet=(
                    "HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS "
                    "http://127.0.0.1:8080/healthz || exit 1"
                ),
                cwe="CWE-693",
                owasp="A05:2021",
                nist="SI-4",
            )
        )
    return findings, suppressed


def _extract_k8s_pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(doc.get("kind") or "")
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        tmpl = spec.get("template")
        if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
            return tmpl["spec"]
    if kind == "CronJob":
        jt = spec.get("jobTemplate")
        if isinstance(jt, dict) and isinstance(jt.get("spec"), dict):
            tmpl = jt["spec"].get("template")
            if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
                return tmpl["spec"]
    return None


def _audit_kubernetes(
    rel_path: str, text: str, docs: list[dict[str, Any]]
) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0

    for doc in docs:
        pod_spec = _extract_k8s_pod_spec(doc)
        if pod_spec is None:
            continue
        kind = str(doc.get("kind") or "Workload")
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        res_name = str(meta.get("name") or "unnamed")

        for host_flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(host_flag) is True:
                ln = _find_line(lines, host_flag)
                if _line_ignored(lines, ln):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-K8S-002",
                            title=f"Kubernetes {kind}/{res_name} enables `{host_flag}: true`",
                            severity="HIGH",
                            category="kubernetes",
                            file_path=rel_path,
                            line=ln,
                            evidence=f"{host_flag}: true breaks container namespace isolation.",
                            remediation=f"Remove `{host_flag}: true` (default is `false`).",
                            cwe="CWE-250",
                            owasp="A05:2021",
                            nist="SC-39",
                        )
                    )

        for vol in pod_spec.get("volumes") or []:
            if not isinstance(vol, dict):
                continue
            hp = vol.get("hostPath")
            if isinstance(hp, dict):
                hp_path = str(hp.get("path") or "").rstrip("/") or "/"
                if hp_path in _SENSITIVE_HOST_PATHS or "docker.sock" in hp_path:
                    ln = _find_line(lines, hp_path)
                    if _line_ignored(lines, ln):
                        suppressed += 1
                    else:
                        sev = "CRITICAL" if "docker.sock" in hp_path or hp_path == "/" else "HIGH"
                        findings.append(
                            ConfigFinding(
                                rule_id="IAC-K8S-003",
                                title=(
                                    f"Sensitive `hostPath` mount `{hp_path}` in {kind}/{res_name}"
                                ),
                                severity=sev,
                                category="kubernetes",
                                file_path=rel_path,
                                line=ln,
                                evidence=f"hostPath.path={hp_path}",
                                remediation=(
                                    "Replace `hostPath` mounts with PVCs, emptyDir, ConfigMaps, or "
                                    "Secrets."
                                ),
                                cwe="CWE-250",
                                owasp="A01:2021",
                                nist="AC-6",
                            )
                        )

        if pod_spec.get("automountServiceAccountToken") is not False:
            ln = _find_line(lines, res_name)
            findings.append(
                ConfigFinding(
                    rule_id="IAC-K8S-009",
                    title=f"Kubernetes {kind}/{res_name} mounts service account token by default",
                    severity="LOW",
                    category="kubernetes",
                    file_path=rel_path,
                    line=ln,
                    evidence="automountServiceAccountToken is not explicitly set to false.",
                    remediation=(
                        "Set `automountServiceAccountToken: false` unless the pod calls the K8s "
                        "API."
                    ),
                    fix_snippet="spec:\n  automountServiceAccountToken: false",
                    cwe="CWE-269",
                    owasp="A01:2021",
                    nist="AC-6",
                )
            )

        pod_sc = (
            pod_spec.get("securityContext")
            if isinstance(pod_spec.get("securityContext"), dict)
            else {}
        )
        containers = [
            c
            for c in [*(pod_spec.get("containers") or []), *(pod_spec.get("initContainers") or [])]
            if isinstance(c, dict)
        ]
        for container in containers:
            cname = str(container.get("name") or "container")
            sc = (
                container.get("securityContext")
                if isinstance(container.get("securityContext"), dict)
                else {}
            )
            c_line = _find_line(lines, cname)

            if sc.get("privileged") is True:
                ln = _find_line(lines, "privileged", start=c_line)
                if _line_ignored(lines, ln):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-K8S-001",
                            title=f"Privileged container `{cname}` in {kind}/{res_name}",
                            severity="CRITICAL",
                            category="kubernetes",
                            file_path=rel_path,
                            line=ln,
                            evidence=(
                                "securityContext.privileged: true grants full host device access."
                            ),
                            remediation="Set `securityContext.privileged: false`.",
                            cwe="CWE-250",
                            owasp="A05:2021",
                            nist="AC-6",
                        )
                    )

            run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
            run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            if run_as_user == 0 or run_as_non_root is not True:
                if _line_ignored(lines, c_line):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-K8S-004",
                            title=f"Container `{cname}` does not enforce `runAsNonRoot: true`",
                            severity="HIGH" if run_as_user == 0 else "MEDIUM",
                            category="kubernetes",
                            file_path=rel_path,
                            line=c_line,
                            evidence=f"runAsNonRoot={run_as_non_root}, runAsUser={run_as_user}",
                            remediation=(
                                "Set `securityContext.runAsNonRoot: true` and a non-zero "
                                "`runAsUser`."
                            ),
                            fix_snippet=(
                                "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001"
                            ),
                            cwe="CWE-250",
                            owasp="A05:2021",
                            nist="AC-6",
                        )
                    )

            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-K8S-005",
                        title=f"Container `{cname}` allows privilege escalation",
                        severity="MEDIUM",
                        category="kubernetes",
                        file_path=rel_path,
                        line=c_line,
                        evidence="securityContext.allowPrivilegeEscalation is not set to false.",
                        remediation="Set `securityContext.allowPrivilegeEscalation: false`.",
                        cwe="CWE-269",
                        owasp="A05:2021",
                        nist="AC-6",
                    )
                )

            caps = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
            added_caps = [str(x).upper() for x in (caps.get("add") or [])]
            bad_caps = sorted(set(added_caps) & _DANGEROUS_CAPS)
            if bad_caps:
                ln = _find_line(lines, "capabilities", start=c_line)
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-K8S-006",
                        title=(
                            f"Container `{cname}` adds dangerous Linux capabilities "
                            f"({', '.join(bad_caps)})"
                        ),
                        severity="CRITICAL"
                        if ("ALL" in bad_caps or "SYS_ADMIN" in bad_caps)
                        else "HIGH",
                        category="kubernetes",
                        file_path=rel_path,
                        line=ln,
                        evidence=f"capabilities.add={bad_caps}",
                        remediation=(
                            "Drop `ALL` capabilities and add only minimal required capabilities."
                        ),
                        fix_snippet="securityContext:\n  capabilities:\n    drop: ['ALL']",
                        cwe="CWE-250",
                        owasp="A05:2021",
                        nist="AC-6",
                    )
                )

            if sc.get("readOnlyRootFilesystem") is not True:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-K8S-007",
                        title=f"Container `{cname}` has writable root filesystem",
                        severity="LOW",
                        category="kubernetes",
                        file_path=rel_path,
                        line=c_line,
                        evidence="securityContext.readOnlyRootFilesystem is not true.",
                        remediation=(
                            "Set `readOnlyRootFilesystem: true` and mount `emptyDir` for `/tmp`."
                        ),
                        cwe="CWE-732",
                        owasp="A05:2021",
                        nist="CM-6",
                    )
                )

            resources = (
                container.get("resources") if isinstance(container.get("resources"), dict) else {}
            )
            limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-K8S-008",
                        title=f"Container `{cname}` missing CPU/memory resource limits",
                        severity="LOW",
                        category="kubernetes",
                        file_path=rel_path,
                        line=c_line,
                        evidence=f"resources.limits={limits or 'unset'}",
                        remediation=(
                            "Define `resources.limits.cpu` and `resources.limits.memory` to "
                            "prevent DoS."
                        ),
                        cwe="CWE-770",
                        owasp="A05:2021",
                        nist="SC-6",
                    )
                )

            img = str(container.get("image") or "")
            if img and "@sha256:" not in img and (":" not in img or img.endswith(":latest")):
                ln = _find_line(lines, img, start=c_line)
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-K8S-010",
                        title=f"Container `{cname}` uses unpinned image `{img}`",
                        severity="MEDIUM",
                        category="kubernetes",
                        file_path=rel_path,
                        line=ln,
                        evidence=f"image: {img}",
                        remediation="Pin container images to immutable tags or `@sha256:` digests.",
                        cwe="CWE-829",
                        owasp="A08:2021",
                        nist="CM-2",
                    )
                )
    return findings, suppressed


def _audit_github_actions(
    rel_path: str, text: str, doc: dict[str, Any]
) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0

    # PyYAML parses bare `on:` as boolean True
    triggers = doc.get("on", doc.get(True))
    has_prt = False
    if isinstance(triggers, str):
        has_prt = triggers == "pull_request_target"
    elif isinstance(triggers, (list, dict)):
        has_prt = "pull_request_target" in triggers

    top_perms = doc.get("permissions")
    if top_perms == "write-all":
        ln = _find_line(lines, "write-all")
        if _line_ignored(lines, ln):
            suppressed += 1
        else:
            findings.append(
                ConfigFinding(
                    rule_id="IAC-GHA-004",
                    title="GitHub Actions workflow grants `permissions: write-all`",
                    severity="HIGH",
                    category="github_actions",
                    file_path=rel_path,
                    line=ln,
                    evidence="permissions: write-all",
                    remediation=(
                        "Restrict top-level `permissions: contents: read` and grant write only per "
                        "job."
                    ),
                    fix_snippet="permissions:\n  contents: read",
                    cwe="CWE-250",
                    owasp="A01:2021",
                    nist="AC-6",
                )
            )
    elif top_perms is None:
        findings.append(
            ConfigFinding(
                rule_id="IAC-GHA-004",
                title="GitHub Actions workflow omits explicit top-level `permissions:` block",
                severity="LOW",
                category="github_actions",
                file_path=rel_path,
                line=1,
                evidence="No top-level `permissions:` declaration found.",
                remediation=(
                    "Declare `permissions: { contents: read }` at workflow top level for least "
                    "privilege."
                ),
                fix_snippet="permissions:\n  contents: read",
                cwe="CWE-250",
                owasp="A01:2021",
                nist="AC-6",
            )
        )

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return findings, suppressed

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses") or "").strip()
            with_cfg = step.get("with") if isinstance(step.get("with"), dict) else {}
            if has_prt and uses.startswith("actions/checkout"):
                ref = str(with_cfg.get("ref") or "")
                if "pull_request.head" in ref:
                    ln = _find_line(lines, "pull_request.head")
                    if _line_ignored(lines, ln):
                        suppressed += 1
                    else:
                        findings.append(
                            ConfigFinding(
                                rule_id="IAC-GHA-001",
                                title=(
                                    "Dangerous `pull_request_target` checkout of untrusted PR "
                                    f"head in job `{job_name}`"
                                ),
                                severity="CRITICAL",
                                category="github_actions",
                                file_path=rel_path,
                                line=ln,
                                evidence=f"uses: {uses} with ref: {ref}",
                                remediation=(
                                    "Use `pull_request` trigger or avoid executing untrusted PR "
                                    "code under `pull_request_target`."
                                ),
                                cwe="CWE-94",
                                owasp="A08:2021",
                                nist="SI-7",
                            )
                        )
            if (
                uses
                and not uses.startswith(("./", "docker://"))
                and "@" in uses
                and not _SHA40_RE.search(uses)
            ):
                ln = _find_line(lines, uses)
                if _line_ignored(lines, ln):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-GHA-003",
                            title=f"GitHub Action `{uses}` not pinned to a full 40-char commit SHA",
                            severity="MEDIUM",
                            category="github_actions",
                            file_path=rel_path,
                            line=ln,
                            evidence=f"uses: {uses}",
                            remediation=(
                                "Pin third-party actions to an immutable 40-character commit SHA."
                            ),
                            fix_snippet=(
                                f"uses: {uses.split('@', 1)[0]}@<40-char-commit-sha> "
                                f"# {uses.split('@', 1)[1]}"
                            ),
                            cwe="CWE-829",
                            owasp="A08:2021",
                            nist="SR-3",
                        )
                    )
            run_block = step.get("run")
            if isinstance(run_block, str):
                for m in _GHA_UNTRUSTED_EXPR_RE.finditer(run_block):
                    expr = m.group(0)
                    ln = _find_line(lines, expr)
                    if _line_ignored(lines, ln):
                        suppressed += 1
                    else:
                        findings.append(
                            ConfigFinding(
                                rule_id="IAC-GHA-002",
                                title=(
                                    "Untrusted GitHub context expression interpolated in `run:` "
                                    f"({job_name})"
                                ),
                                severity="CRITICAL",
                                category="github_actions",
                                file_path=rel_path,
                                line=ln,
                                evidence=expr,
                                remediation=(
                                    "Pass untrusted context values through `env:` and reference "
                                    "them as quoted shell variables."
                                ),
                                fix_snippet=(
                                    "env:\n  UNTRUSTED_VAL: ${{ github.event.issue.title }}\nrun: "
                                    'echo "$UNTRUSTED_VAL"'
                                ),
                                cwe="CWE-78",
                                owasp="A03:2021",
                                nist="SI-10",
                            )
                        )
    return findings, suppressed


def _audit_docker_compose(
    rel_path: str, text: str, doc: dict[str, Any]
) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0
    services = doc.get("services")
    if not isinstance(services, dict):
        return findings, suppressed

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        s_line = _find_line(lines, f"{svc_name}:")
        if svc.get("privileged") is True:
            ln = _find_line(lines, "privileged", start=s_line)
            if _line_ignored(lines, ln):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-COMP-001",
                        title=f"Docker Compose service `{svc_name}` runs `privileged: true`",
                        severity="CRITICAL",
                        category="docker_compose",
                        file_path=rel_path,
                        line=ln,
                        evidence="privileged: true",
                        remediation=(
                            "Remove `privileged: true` and grant only specific needed "
                            "devices/capabilities."
                        ),
                        cwe="CWE-250",
                        owasp="A05:2021",
                        nist="AC-6",
                    )
                )
        for mode_key in ("network_mode", "pid"):
            if str(svc.get(mode_key) or "").lower() == "host":
                ln = _find_line(lines, mode_key, start=s_line)
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-COMP-002",
                        title=(
                            f"Docker Compose service `{svc_name}` shares host namespace "
                            f"(`{mode_key}: host`)"
                        ),
                        severity="HIGH",
                        category="docker_compose",
                        file_path=rel_path,
                        line=ln,
                        evidence=f"{mode_key}: host",
                        remediation=(
                            f"Use an isolated bridge network instead of `{mode_key}: host`."
                        ),
                        cwe="CWE-250",
                        owasp="A05:2021",
                        nist="SC-39",
                    )
                )
        for vol in svc.get("volumes") or []:
            vol_s = str(vol)
            if "docker.sock" in vol_s:
                ln = _find_line(lines, "docker.sock", start=s_line)
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-COMP-003",
                        title=f"Docker Compose service `{svc_name}` mounts Docker socket",
                        severity="CRITICAL",
                        category="docker_compose",
                        file_path=rel_path,
                        line=ln,
                        evidence=vol_s[:120],
                        remediation=(
                            "Avoid mounting `/var/run/docker.sock` (grants root-equivalent host "
                            "control)."
                        ),
                        cwe="CWE-250",
                        owasp="A01:2021",
                        nist="AC-6",
                    )
                )
        for port in svc.get("ports") or []:
            p_str = str(port).strip().strip('"').strip("'")
            if ":" in p_str and not p_str.startswith(("127.0.0.1:", "localhost:", "[::1]:")):
                host_port = p_str.split(":")[0]
                cont_port = p_str.split(":")[-1].split("/")[0]
                if host_port in _DB_PORTS or cont_port in _DB_PORTS:
                    ln = _find_line(lines, p_str, start=s_line)
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-COMP-004",
                            title=(
                                f"Database/cache port `{p_str}` in `{svc_name}` bound on all "
                                "interfaces (`0.0.0.0`)"
                            ),
                            severity="HIGH",
                            category="docker_compose",
                            file_path=rel_path,
                            line=ln,
                            evidence=f"ports: [{p_str}]",
                            remediation=(
                                f"Bind internal datastores to loopback: `127.0.0.1:{p_str}`."
                            ),
                            fix_snippet=f'ports:\n  - "127.0.0.1:{p_str}"',
                            cwe="CWE-668",
                            owasp="A05:2021",
                            nist="SC-7",
                        )
                    )
        cap_add = [str(c).upper() for c in (svc.get("cap_add") or [])]
        bad_caps = sorted(set(cap_add) & _DANGEROUS_CAPS)
        if bad_caps:
            ln = _find_line(lines, "cap_add", start=s_line)
            findings.append(
                ConfigFinding(
                    rule_id="IAC-COMP-005",
                    title=(
                        f"Docker Compose service `{svc_name}` adds dangerous capabilities "
                        f"({', '.join(bad_caps)})"
                    ),
                    severity="HIGH",
                    category="docker_compose",
                    file_path=rel_path,
                    line=ln,
                    evidence=f"cap_add: {bad_caps}",
                    remediation=(
                        "Use `cap_drop: [ALL]` and remove unnecessary privileged capabilities."
                    ),
                    cwe="CWE-250",
                    owasp="A05:2021",
                    nist="AC-6",
                )
            )
    return findings, suppressed


def _audit_nginx(rel_path: str, text: str) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0
    has_server_tokens_off = False
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "server_tokens" in low and "off" in low:
            has_server_tokens_off = True
        if low.startswith("ssl_protocols") and any(
            bad in low for bad in ("sslv2", "sslv3", "tlsv1 ", "tlsv1;", "tlsv1.0", "tlsv1.1")
        ):
            if _line_ignored(lines, idx):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-NGX-001",
                        title="NGINX enables deprecated SSL/TLS protocol versions",
                        severity="HIGH",
                        category="nginx",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped[:140],
                        remediation="Restrict to `ssl_protocols TLSv1.2 TLSv1.3;`.",
                        fix_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
                        cwe="CWE-327",
                        owasp="A02:2021",
                        nist="SC-8",
                    )
                )
        if re.search(r"\bautoindex\s+on\b", low):
            if _line_ignored(lines, idx):
                suppressed += 1
            else:
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-NGX-002",
                        title="NGINX enables directory listing (`autoindex on`)",
                        severity="MEDIUM",
                        category="nginx",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped[:140],
                        remediation="Set `autoindex off;` to prevent unintended file disclosure.",
                        fix_snippet="autoindex off;",
                        cwe="CWE-548",
                        owasp="A05:2021",
                        nist="CM-7",
                    )
                )
        if re.search(r"\bproxy_ssl_verify\s+off\b", low):
            findings.append(
                ConfigFinding(
                    rule_id="IAC-NGX-004",
                    title=(
                        "NGINX disables upstream TLS certificate verification (`proxy_ssl_verify "
                        "off`)"
                    ),
                    severity="HIGH",
                    category="nginx",
                    file_path=rel_path,
                    line=idx,
                    evidence=stripped[:140],
                    remediation="Enable `proxy_ssl_verify on;` with a trusted CA bundle.",
                    cwe="CWE-295",
                    owasp="A02:2021",
                    nist="SC-8",
                )
            )
    if not has_server_tokens_off and "server {" in text:
        findings.append(
            ConfigFinding(
                rule_id="IAC-NGX-003",
                title="NGINX config omits `server_tokens off;`",
                severity="LOW",
                category="nginx",
                file_path=rel_path,
                line=1,
                evidence="server_tokens off not detected in NGINX config.",
                remediation="Add `server_tokens off;` in the `http` or `server` block.",
                fix_snippet="server_tokens off;",
                cwe="CWE-200",
                owasp="A05:2021",
                nist="CM-6",
            )
        )
    return findings, suppressed


def _audit_env_or_sshd(rel_path: str, text: str, *, kind: str) -> tuple[list[ConfigFinding], int]:
    lines = text.splitlines()
    findings: list[ConfigFinding] = []
    suppressed = 0
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        if kind == "env":
            if re.match(r"^(?:DEBUG|FLASK_DEBUG|APP_DEBUG)\s*=\s*(?:true|1|yes)$", stripped, re.I):
                if _line_ignored(lines, idx):
                    suppressed += 1
                else:
                    findings.append(
                        ConfigFinding(
                            rule_id="IAC-ENV-001",
                            title="Debug mode enabled in environment file",
                            severity="MEDIUM",
                            category="env",
                            file_path=rel_path,
                            line=idx,
                            evidence=stripped,
                            remediation="Disable debug flags in production (`DEBUG=false`).",
                            cwe="CWE-489",
                            owasp="A05:2021",
                            nist="CM-6",
                        )
                    )
            if re.match(r"^NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0$", stripped, re.I):
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-ENV-002",
                        title=(
                            "TLS certificate verification globally disabled "
                            "(`NODE_TLS_REJECT_UNAUTHORIZED=0`)"
                        ),
                        severity="CRITICAL",
                        category="env",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped,
                        remediation=(
                            "Remove `NODE_TLS_REJECT_UNAUTHORIZED=0` and configure "
                            "`NODE_EXTRA_CA_CERTS`."
                        ),
                        cwe="CWE-295",
                        owasp="A02:2021",
                        nist="SC-8",
                    )
                )
        else:  # sshd
            low = stripped.lower()
            if re.match(r"^permitrootlogin\s+yes\b", low):
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-SSH-001",
                        title="OpenSSH permits direct root login (`PermitRootLogin yes`)",
                        severity="HIGH",
                        category="sshd",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped,
                        remediation=(
                            "Set `PermitRootLogin no` (or `prohibit-password` if strictly needed)."
                        ),
                        fix_snippet="PermitRootLogin no",
                        cwe="CWE-250",
                        owasp="A07:2021",
                        nist="AC-6",
                    )
                )
            elif re.match(r"^passwordauthentication\s+yes\b", low):
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-SSH-002",
                        title=(
                            "OpenSSH permits password authentication (`PasswordAuthentication yes`)"
                        ),
                        severity="MEDIUM",
                        category="sshd",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped,
                        remediation=(
                            "Set `PasswordAuthentication no` and enforce SSH key / FIDO2 "
                            "authentication."
                        ),
                        fix_snippet="PasswordAuthentication no",
                        cwe="CWE-307",
                        owasp="A07:2021",
                        nist="IA-2",
                    )
                )
            elif re.match(r"^permitemptypasswords\s+yes\b", low):
                findings.append(
                    ConfigFinding(
                        rule_id="IAC-SSH-003",
                        title="OpenSSH permits empty passwords (`PermitEmptyPasswords yes`)",
                        severity="CRITICAL",
                        category="sshd",
                        file_path=rel_path,
                        line=idx,
                        evidence=stripped,
                        remediation="Set `PermitEmptyPasswords no` immediately.",
                        fix_snippet="PermitEmptyPasswords no",
                        cwe="CWE-287",
                        owasp="A07:2021",
                        nist="IA-5",
                    )
                )
    return findings, suppressed


def _classify_and_audit_file(
    item: Path, rel_str: str
) -> tuple[str | None, list[ConfigFinding], int]:
    name = item.name.lower()
    rel_low = rel_str.lower()

    if (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
        or name == "containerfile"
    ):
        text = item.read_text(encoding="utf-8", errors="replace")
        f, s = _audit_dockerfile(rel_str, text)
        return "dockerfile", f, s

    if name.endswith((".nginx", ".conf")) and ("nginx" in rel_low or name == "nginx.conf"):
        text = item.read_text(encoding="utf-8", errors="replace")
        f, s = _audit_nginx(rel_str, text)
        return "nginx", f, s

    if name.startswith("sshd_config"):
        text = item.read_text(encoding="utf-8", errors="replace")
        f, s = _audit_env_or_sshd(rel_str, text, kind="sshd")
        return "sshd", f, s

    if (name == ".env" or name.startswith(".env.")) and not name.endswith(
        (".example", ".sample", ".template")
    ):
        text = item.read_text(encoding="utf-8", errors="replace")
        f, s = _audit_env_or_sshd(rel_str, text, kind="env")
        return "env", f, s

    if name.endswith((".yml", ".yaml")):
        text = item.read_text(encoding="utf-8", errors="replace")
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError:
            return None, [], 0
        if not docs:
            return None, [], 0

        if ".github/workflows/" in rel_low or (
            len(docs) == 1 and "jobs" in docs[0] and ("on" in docs[0] or True in docs[0])
        ):
            f, s = _audit_github_actions(rel_str, text, docs[0])
            return "github_actions", f, s

        if any("apiVersion" in d and "kind" in d for d in docs):
            k8s_docs = [d for d in docs if "apiVersion" in d and "kind" in d]
            f, s = _audit_kubernetes(rel_str, text, k8s_docs)
            return "kubernetes", f, s

        if (
            len(docs) == 1
            and isinstance(docs[0].get("services"), dict)
            and (
                "compose" in name
                or "version" in docs[0]
                or any(
                    isinstance(v, dict) and ("image" in v or "build" in v)
                    for v in docs[0]["services"].values()
                )
            )
        ):
            f, s = _audit_docker_compose(rel_str, text, docs[0])
            return "docker_compose", f, s

    return None, [], 0


def scan_config(path: Path) -> ConfigScanResult:
    """Audit Dockerfiles, K8s manifests, GitHub Actions, Compose, NGINX, SSHd, and .env files."""
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValidationError(f"Config scan target does not exist: '{path}'.")

    files = (
        [resolved] if resolved.is_file() else sorted(p for p in resolved.rglob("*") if p.is_file())
    )
    findings: list[ConfigFinding] = []
    file_types: dict[str, int] = {}
    files_scanned = 0
    suppressed_total = 0

    for item in files:
        rel_str = str(path) if resolved.is_file() else item.relative_to(resolved).as_posix()
        if not resolved.is_file():
            rel_parts = item.relative_to(resolved).parts
            if any(part in _SKIP_DIRS for part in rel_parts[:-1]):
                continue
        try:
            if item.stat().st_size > 2 * 1024 * 1024:
                continue
            ftype, f_list, sup = _classify_and_audit_file(item, rel_str)
        except OSError:
            continue
        if ftype is not None:
            files_scanned += 1
            file_types[ftype] = file_types.get(ftype, 0) + 1
            findings.extend(f_list)
            suppressed_total += sup

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.file_path, f.line, f.rule_id))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    highest = findings[0].severity if findings else None

    return ConfigScanResult(
        target_path=str(path),
        files_scanned=files_scanned,
        file_types=file_types,
        suppressed_count=suppressed_total,
        findings=findings,
        severity_counts=counts,
        highest_severity=highest,
    )
