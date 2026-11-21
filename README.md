<a id="top"></a>

<div align="center">

<img src="docs/assets/s1shell-banner.svg" alt="S1shell — Authorized Defensive Security Assessment & OSINT Toolkit" width="100%" />

<br />
<br />

[![Version](https://img.shields.io/badge/Version-0.5.0-0ea5e9?style=for-the-badge)](CHANGELOG.md)
[![Dev](https://img.shields.io/badge/Dev-Willy_Gailo_RVS-f59e0b?style=for-the-badge)](#top)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Platform](https://img.shields.io/badge/Kali_Linux-Linux-557c94?style=for-the-badge&logo=kalilinux&logoColor=white)](scripts/install-kali.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-22c55e?style=for-the-badge)](.github/workflows/ci.yml)
[![MCP](https://img.shields.io/badge/MCP_Server-Online_HTTP_%2B_Stdio-8b5cf6?style=for-the-badge)](#online-and-local-mcp-server-s1shell-mcp-serve)
[![AI Skills](https://img.shields.io/badge/Defensive_AI-10_Skills_%2B_ReAct-06b6d4?style=for-the-badge)](#defensive-ai-skills)
[![Tor](https://img.shields.io/badge/Tor-Zero--Leak_SOCKS5h-7c3aed?style=for-the-badge)](#defensive-tor-routing)

<br />

**Open-source defensive security assessment, local secret/IaC/SBOM scanning, deep CSP/email/CVSS analysis, passive OSINT, AI triage, and reporting CLI built for Kali Linux & Linux.**

[⚡ Setup & Install](#part-1-setup--configuration) &nbsp;·&nbsp;
[🔑 API Keys & Logins](#13-configure-optional-api-keys--ai-provider-env-atomic-0600) &nbsp;·&nbsp;
[🔐 Local Scan (`scan`)](#43-local-secret-scanning-iacconfig-auditing--cyclonedx-15-sbom-s1shell-scan) &nbsp;·&nbsp;
[🔬 Deep Analyzers (`analyze`)](#44-deep-offline-csp3-email-auth-header--cvss-analyzers-s1shell-analyze) &nbsp;·&nbsp;
[🌐 Online MCP](#online-and-local-mcp-server-s1shell-mcp-serve) &nbsp;·&nbsp;
[🧅 Tor Routing](#defensive-tor-routing) &nbsp;·&nbsp;
[🎯 Pentesting Guide (`target.com`)](#part-2-pentesting--assessment-guide-example-httpswwwtargetcom) &nbsp;·&nbsp;
[🧠 AI Skills](#defensive-ai-skills) &nbsp;·&nbsp;
[📖 CLI Reference](#part-3-reference-cicd--troubleshooting)

</div>

---

## Architecture Overview

```mermaid
flowchart LR
    CLI["s1shell CLI\n(18 Modules · --tor / --tor-targets)"] --> GATE["Policy Gate\nScope -> Auth -> IP Pin / Tor SOCKS5h -> SHA-256 Audit"]
    CLI --> INTEL["Zero-Target-Contact Intel\n7 Feeds · SQLite Cache · Optional --tor"]
    CLI --> AI["Defensive AI Engine\n10 Skills · Pipelines · ReAct (14 Tools) · Builtin"]
    CLI --> OFFLINE["Offline Tools & Online MCP\nScan · Analyze · Codec · Remediate · Diff · MCP"]

    GATE --> TARGET["profile · fingerprint · assess\nClearnet + Authorized v3 .onion"]
    INTEL --> FEEDS["NVD · CVE.org · OSV.dev · KEV · EPSS\nVT · GreyNoise · urlscan · GHSA · crt.sh · RDAP"]
    AI --> MODELS["Builtin Offline · Local Ollama (--local-only)\nAnthropic · OpenAI-Compat · Gemini"]
    OFFLINE --> OUT["HTML · MD · JSON · SARIF 2.1.0 · CycloneDX 1.5\n30–33 MCP Tools · Resources · Prompts"]

    style CLI fill:#0f172a,stroke:#38bdf8,color:#f8fafc
    style GATE fill:#0f172a,stroke:#f59e0b,color:#f8fafc
    style INTEL fill:#0f172a,stroke:#22d3ee,color:#f8fafc
    style AI fill:#0f172a,stroke:#a78bfa,color:#f8fafc
    style OFFLINE fill:#0f172a,stroke:#34d399,color:#f8fafc
```

---

## Key Capabilities

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🛡️ Fail-Closed Scope &amp; Governance</h3>
      Allow/deny (<code>--exclude</code>) rules for domains, IPs, CIDRs, URL prefixes, and <b>Tor v3 <code>.onion</code></b>, bulk import (<code>--dry-run</code>), DNS rebinding + private/CGNAT (<code>100.64.0.0/10</code>)/NAT64 (<code>64:ff9b::/96</code>)/IPv4-mapped IPv6/metadata guards, IP-pinned HTTP/TLS, atomic <code>0600</code> writes, and a file-locked (<code>fcntl.flock</code>) <code>O(1)</code> SHA-256 hash-chained <code>audit.log</code>.
    </td>
    <td width="50%" valign="top">
      <h3>🔍 Deep Pentest Target Profiling &amp; Entity Extraction</h3>
      Recursive RFC 7208 <code>SPF</code> + void/loop checks, <code>DMARC</code>/<code>MTA-STS</code>/<code>TLS-RPT</code>/<code>BIMI</code>/<code>DANE TLSA</code>/<code>DNSSEC</code>/33-provider CNAME takeover checks, full X.509 cert chains + Subject/Serial/SPKI pin, CSP v2/CORS/HSTS/cookies, plus zero-extra-packet extraction of <b>Names/Organizations (<code>meta</code> + <code>JSON-LD</code>), Emails &amp; <code>[Gmail]</code> contacts, Phone numbers (<code>+63</code>/PH/intl), Exposed Keys &amp; Client/App IDs (GA4, GTM, Firebase, Stripe, OAuth, reCAPTCHA, GCP/AWS/GitHub/OpenAI/Telegram/Slack/Discord/Twilio/SendGrid/Mailgun, JWTs), Form Actions &amp; High-Interest Input Parameters (<code>redirect_uri*</code>, <code>file*</code>, <code>id*</code>, <code>token*</code>), Internal IPs &amp; Dev Comments, Social links, Cloud buckets, and API paths</b>.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧬 81 Passive Fingerprints &amp; 30-Product Offline EOL DB</h3>
      Identifies web servers, CDNs, WAFs, DevOps platforms, frameworks, and client-side JS libraries (<code>jQuery</code>, <code>Bootstrap</code>, <code>Lodash</code>, <code>Moment.js</code>, <code>DOMPurify</code>, <code>Handlebars</code>, <code>Axios</code>, <code>Swagger UI</code>) with CPE 2.3 correlation, expanded offline <b>End-of-Life (<code>EOL-001</code>)</b> detection (NGINX, Apache, PHP, Python, Node.js, OpenSSL, Envoy, Traefik, Varnish, Django, Rails, Laravel, Next.js, PostgreSQL, MySQL, Redis, OpenSSH, Grafana, Jenkins, etc.), and custom <code>~/.s1shell/signatures.d/*.yaml</code> rules.
    </td>
    <td width="50%" valign="top">
      <h3>📦 CVE, KEV, EPSS, GHSA &amp; 14-Format SBOM Audit</h3>
      NVD 2.0 + CVE.org + GHSA + CISA KEV + FIRST EPSS with SSVC <code>P0-IMMEDIATE</code>..<code>P3-MONITOR</code> tiers &amp; pure-Python CVSS v3.0/v3.1 Base/Temporal/Environmental scoring, plus recursive zero-contact <b>OSV.dev</b> lockfile &amp; CycloneDX / <b>SPDX 2.3</b> SBOM auditing with semantic highest-version upgrade commands.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🔐 Local Secret, IaC/Config &amp; CycloneDX 1.5 SBOM Scanner (<code>scan</code>)</h3>
      Zero-network local repository &amp; git-diff security scanner: <b>27+ redacted secret detectors</b> (AWS/GCP/Azure/GitHub/GitLab/Anthropic/OpenAI/Stripe/Slack/DB URIs/PEM keys + Shannon entropy &amp; <code>--git-staged</code>), <b>IaC &amp; config auditor</b> (Dockerfiles, K8s manifests, GitHub Actions pwn-request/expression-injection, Docker Compose, NGINX, <code>.env</code>, <code>sshd_config</code>) with line/column-accurate <b>SARIF 2.1.0</b> &amp; <code>--fail-on</code> CI gates, plus <b>CycloneDX 1.5 SBOM generation</b>.
    </td>
    <td width="50%" valign="top">
      <h3>🔬 Deep CSP3, Email Auth, Offline Header &amp; CVSS Analyzers (<code>analyze</code>)</h3>
      Purpose-built security analyzers: <b>CSP3 Evaluator</b> (28-domain JSONP/script-gadget bypass DB, duplicate/typo directives, nonce entropy, hardened rewrite), <b>Email Spoofing Defense Auditor</b> (SPF IPv4 CIDR blast radius &amp; lookup budget, DMARC alignment, cryptographic DKIM DER key bit-length check), <b>100%-offline raw HTTP header posture scorer</b>, and <b>FIRST CVSS v3.0/v3.1 + v4.0 calculator</b>.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🌐 7-Feed Passive Threat Intel &amp; OSINT</h3>
      Cached, zero-target-contact lookups with bounded HTTP <code>429</code>/<code>502</code>/<code>503</code>/<code>504</code> <code>Retry-After</code> backoff across <b>VirusTotal v3</b>, <b>GreyNoise Community</b>, <b>urlscan.io Search</b>, <b>GHSA</b>, <b>NVD</b>, plus zero-API-key <b>Certificate Transparency (<code>crt.sh</code>)</b> and <b>RDAP</b> (including vCard registrant/abuse emails, phone numbers, and entity roles/handles).
    </td>
    <td width="50%" valign="top">
      <h3>🔧 Playbooks, Presets, Drift Diffs &amp; SARIF</h3>
      Posture presets (<code>web</code>, <code>api</code>, <code>strict</code>), transparent waivers (<code>--ignore-finding</code>), OWASP Top 10:2021 / ASVS / CWE / NIST 800-53 mapping, offline config snippets (<code>nginx</code>, <code>apache</code>, <code>caddy</code>, <code>express</code>, <code>cloudflare</code>, <code>traefik</code>, <code>dns</code>, <code>security.txt</code>, CORS/SRI/OIDC/LEAK), <code>diff --fail-on-regression</code>, and CI gates (<code>exit 4</code>).
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧪 Offline CyberChef-Style Codec &amp; Inspector</h3>
      Zero-network <code>s1shell codec decode|encode|inspect|hash</code> across 25 codecs (Base64/32/58/85, Hex, URL, HTML, Unicode, Punycode, ROT13/Caesar, Gzip/Zlib/Deflate, SAML XML, JWT, auto magic peeling), X.509 PEM/DER inspection, hash ID, and Shannon entropy.
    </td>
    <td width="50%" valign="top">
      <h3>🧠 Defensive AI Skills, Pipelines &amp; ReAct Copilot</h3>
      Offline <b>Builtin</b> tactical synthesizer, air-gapped <b>Ollama</b> (<code>--local-only</code>), <b>Anthropic</b> (<code>sk-ant-api*</code> &amp; <code>sk-ant-usr*</code> + <code>ANTHROPIC_WORKSPACE_ID</code>), <b>OpenAI-compat</b>, &amp; <b>Gemini</b> with <b>10 defensive AI skills</b> (+ custom <code>~/.s1shell/skills.d/*.yaml</code>), <code>--pipeline</code> workflows, <code>--structured</code> JSON, nonce-tagged prompt-injection guardrails, reversible NDA redaction (<code>--redact --restore</code>), citation grounding checks, bounded read-only <code>ai investigate</code> (<b>14 tools</b>) &amp; <code>ai chat</code>.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>📡 Online Streamable HTTP &amp; Local Stdio MCP</h3>
      Pure-stdlib MCP <code>2025-03-26</code> server (<code>s1shell mcp serve|config|ping</code>) exposing <b>30 default read-only tools</b> (+3 opt-in scoped target tools = <b>33</b>), <b>4 live Resources</b>, and <b>10+ native Prompts</b>, hardened with Bearer auth, <code>Origin</code> DNS-rebinding guard, and <code>/healthz</code>.
    </td>
    <td width="50%" valign="top">
      <h3>🧅 Zero-Leak Defensive Tor (<code>socks5h://</code>) &amp; v3 <code>.onion</code></h3>
      Fail-closed <code>--tor</code> Analyst OPSEC for passive OSINT/CVE/SBOM/Cloud AI (auto-bypassing local Ollama/MCP), plus opt-in <code>--tor --tor-targets</code> routing target DoH DNS, SOCKS5h TLS handshakes, and single-GET HTTP with zero IP/DNS leaks, Direct-vs-Tor WAF diffs, and authorized v3 <code>.onion</code> auditing.
    </td>
  </tr>
</table>

---

## Authorized-Use Notice & Policy Boundaries

> [!CAUTION]
> **Authorized Use Only:** S1shell is strictly intended for systems you **own** or have **explicit written authorization** to evaluate. Every target-touching operation enforces a mandatory **fail-closed policy gate**:
>
> 1. **Scope First (`exit 2`):** No packet is sent unless the target and its resolved IPs match an active, unexpired allow rule (and no `--exclude` rule, including IPv4-mapped IPv6/NAT64 unwrapping) in `~/.s1shell/scope.yaml`, blocking un-scoped loopback, private, CGNAT (`100.64.0.0/10`), NAT64 (`64:ff9b::/96`), and cloud metadata IPs.
> 2. **Explicit Authorization (`exit 3`):** Requires `--authorized` or interactive TTY confirmation; non-interactive runs without `--authorized` fail immediately.
> 3. **Tamper-Evident Audit Logging:** Every network attempt appends a file-locked (`fcntl.flock`), SHA-256 hash-chained JSONL record to `~/.s1shell/audit.log` (`0600`), verifiable offline via `s1shell audit verify`.

### What S1shell Does Not Do

By design, S1shell **never** implements or accepts plugins for:

- Exploitation, exploit payloads, or vulnerability PoC execution
- Payload generation or active vulnerability probing/fuzzing (SQLi/XSS/SSRF/LFI strings)
- WAF bypass, firewall evasion, request smuggling, or browser User-Agent spoofing
- Rate-limit evasion, proxy rotation, or IP rotation
- Brute force, password spraying, credential testing, or directory/subdomain enumeration
- Port scanning, host discovery, denial-of-service testing, or target state modification

---

## Part 1: Setup & Configuration

Complete these steps **once** on your Kali Linux or Linux workstation before starting an engagement.

### 1.1 Install S1shell

```bash
git clone https://github.com/willygailo/ProjectPY.git
cd ProjectPY
```

<table>
  <tr>
    <th width="33%">🐉 Option A — Kali Linux (Recommended)</th>
    <th width="34%">📦 Option B — Standard Linux (<code>pipx</code>)</th>
    <th width="33%">🛠️ Option C — Contributor / Dev</th>
  </tr>
  <tr>
    <td valign="top">
      Checks Python <code>3.10+</code>, installs apt prerequisites (<code>python3-venv</code>, <code>python3-pip</code>, <code>pipx</code>), installs <code>s1shell</code> globally (or <code>.venv</code> with <code>--dev</code>), and runs <code>s1shell doctor</code>:
      <br /><br />
      <pre><code>./scripts/install-kali.sh
# Editable dev venv:
./scripts/install-kali.sh --dev</code></pre>
    </td>
    <td valign="top">
      Installs <code>s1shell</code> in an isolated <code>pipx</code> environment on your <code>PATH</code>:
      <br /><br />
      <pre><code>pipx ensurepath
pipx install .

# Auto-reflect local edits

pipx install --editable --force .</code></pre>
    </td>
    <td valign="top">
      Creates local <code>.venv</code> and runs the full offline lint, strict typecheck, and test suite:
      <br /><br />
      <pre><code>make setup
source .venv/bin/activate
make check</code></pre>
    </td>
  </tr>
</table>

> [!TIP]
> **Seeing `zsh: command not found: s1shell` or `bash: s1shell: command not found`?**
>
> 1. Install the CLI first (`./scripts/install-kali.sh` or `pipx install --editable --force .`).
> 2. Ensure `~/.local/bin` is on your `PATH`, then refresh your shell command cache:
>
>    ```bash
>    export PATH="$HOME/.local/bin:$PATH"
>    rehash          # zsh (or `hash -r` in bash)
>    which s1shell   # expected: ~/.local/bin/s1shell
>    ```
>
> 3. Or run straight from source with zero installation: `PYTHONPATH=src python3 -m s1shell doctor`

### 1.2 Verify Your Setup

```bash
s1shell --version         # expected: s1shell 0.5.0 (Dev: Willy Gailo RVS)
s1shell --check           # live local diagnostics (doctor) + complete CLI usage guide
s1shell help              # CLI overview, all modules, workflows, flags, & exit codes
s1shell help assess       # detailed options & copy-paste examples for any module
s1shell help --all        # complete CLI reference manual (supports --format md --out GUIDE.md)
s1shell doctor            # expected: healthy=True, active scope entries, 81 signatures, 10 AI skills
s1shell scope list        # expected: active TLD & localhost rules (.com, .ph, .com.ph, .gov.ph, ...)
s1shell ai skills list    # expected: 10 bundled defensive AI skills
s1shell tor status        # offline check for local Tor daemon & socksio readiness
s1shell audit verify      # expected: Audit Log Integrity: VALID
```

> [!NOTE]
> If `s1shell doctor` shows `WARN` on `anthropic_api_key`, verify your `.env` contains either a workspace-scoped `sk-ant-api03-*` key or a user-scoped `sk-ant-usr-*` key paired with `ANTHROPIC_WORKSPACE_ID` (`s1shell ai env --workspace-id wrkspc_...`) — not an `sk-ant-admin*` admin key. You can also run zero-cost offline analysis with `--provider builtin` or air-gapped Ollama (`s1shell ai env --provider ollama`).

### 1.3 Configure Optional API Keys & AI Provider (`.env`, Atomic `0600`)

All API keys are **optional** — S1shell works out of the box with unauthenticated NVD, CVE.org, OSV.dev, `crt.sh`, and RDAP. Keys are written atomically with `0600` permissions (gitignored and always masked in output) and resolve in order: **process environment → project `./.env` → `~/.s1shell/.env`** (see [.env.example](.env.example)).

#### Step 1 — Log In & Get Your API Keys / Tokens

| Service | CLI Flag / Env Variable | Where to Log In & Get Key | Purpose |
| --- | --- | --- | --- |
| **NVD (NIST)** | `--set-nvd-key` / `NVD_API_KEY` | [Request NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) | Raises NVD 2.0 quota from 5 req/30s to 50 req/30s |
| **GitHub (GHSA)** | `--set-github-key` / `GITHUB_TOKEN` | [GitHub Personal Access Tokens](https://github.com/settings/tokens) | Authenticates GitHub Security Advisories & CVE enrichment |
| **VirusTotal v3** | `--set-vt-key` / `VIRUSTOTAL_API_KEY` | [Sign Up](https://www.virustotal.com/gui/join-us) · [My API Key](https://www.virustotal.com/gui/my-apikey) | Passive domain/IP reputation lookups |
| **GreyNoise Community** | `--set-greynoise-key` / `GREYNOISE_API_KEY` | [Sign Up](https://viz.greynoise.io/signup) · [Account API Key](https://viz.greynoise.io/account/api-key) | Passive IP scanner noise & benign RIOT lookup |
| **urlscan.io** | `--set-urlscan-key` / `URLSCAN_API_KEY` | [Sign Up](https://urlscan.io/signup) · [Settings & API](https://urlscan.io/user/#settings) | Strictly passive historical Search API index lookup |
| **Ollama (Local AI)** | `--provider ollama` | [Download Ollama](https://ollama.com/download) *(no account / no key needed)* | Air-gapped local LLM triage with zero cloud telemetry |
| **Anthropic Claude** | `--provider anthropic` / `ANTHROPIC_API_KEY`, `ANTHROPIC_WORKSPACE_ID` (`--workspace-id`), `ANTHROPIC_MODEL` | [Anthropic Console Keys](https://console.anthropic.com/settings/keys) *(use `sk-ant-api03-*`, or `sk-ant-usr-*` + `--workspace-id wrkspc_...`; not `sk-ant-admin*`)* | Cloud defensive AI triage & remediation (e.g. `claude-sonnet-5-5`, `claude-sonnet-4-5`) |
| **OpenAI-Compatible** | `--provider openai_compat` / `OPENAI_API_KEY` | [OpenAI API Keys](https://platform.openai.com/api-keys) | OpenAI, OpenRouter, LiteLLM, or vLLM inference |
| **Google Gemini** | `--provider gemini` / `GEMINI_API_KEY` | [Google AI Studio API Keys](https://aistudio.google.com/apikey) | Google Gemini defensive AI inference |
| **Online MCP Server** | `--token` / `S1SHELL_MCP_TOKEN` | Local random secret *(or `--generate-token`)* | Required Bearer auth for non-loopback `--transport http` MCP binds |
| **Tor SOCKS5h** | `--tor` / `S1SHELL_TOR`, `S1SHELL_TOR_TARGETS`, `S1SHELL_TOR_PROXY` | Local Tor daemon *(default `socks5h://127.0.0.1:9050`)* | Zero-DNS-leak Analyst OPSEC & opt-in zero-leak target/v3 `.onion` routing |
| **State Directory** | `S1SHELL_HOME` | Local path override *(default `~/.s1shell`)* | Stores `scope.yaml`, `audit.log`, `cache.db`, & `.env` |

#### Step 2 — Save Keys via CLI (`0600`)

```bash
# Save passive threat-intelligence & CVE quota keys (pass only the keys you have)
s1shell intel env \
  --set-nvd-key "YOUR_NVD_KEY" \
  --set-github-key "YOUR_GITHUB_TOKEN" \
  --set-vt-key "YOUR_VT_KEY" \
  --set-greynoise-key "YOUR_GREYNOISE_KEY" \
  --set-urlscan-key "YOUR_URLSCAN_KEY"

# Verify masked threat-intel key status
s1shell intel env

# Configure local air-gapped Ollama (zero cloud telemetry):
s1shell ai env --provider ollama --model "llama3.1:8b"

# Or configure a cloud AI provider (Anthropic / OpenAI-compatible / Gemini):
# Workspace-scoped Anthropic key (`sk-ant-api03-...`):
# s1shell ai env --provider anthropic --set-key "sk-ant-api03-..." --model "claude-sonnet-5-5"
# User-scoped Anthropic key (`sk-ant-usr-...`) with Workspace ID:
# s1shell ai env --provider anthropic --set-key "sk-ant-usr-..." --workspace-id "wrkspc_..." --model "claude-sonnet-5-5"
# Built-in offline tactical synthesizer (zero API key / zero network):
# s1shell ai env --provider builtin
# s1shell ai env --provider openai_compat --set-key "sk-..." --model "gpt-4o-mini"
# s1shell ai env --provider gemini --set-key "AIza..." --model "gemini-2.5-flash"
```

### 1.4 Optional Setup (Shell Completion, Custom Rules, Online MCP Server & Tor)

<details>
<summary><b>⌨️ Shell Tab-Completion (bash, zsh, fish)</b></summary>

```bash
# Bash
mkdir -p ~/.local/share/bash-completion/completions
s1shell completion bash > ~/.local/share/bash-completion/completions/s1shell

# Zsh
mkdir -p ~/.zsh/completions
s1shell completion zsh > ~/.zsh/completions/_s1shell

# Fish
mkdir -p ~/.config/fish/completions
s1shell completion fish > ~/.config/fish/completions/s1shell.fish
```

</details>

<details>
<summary><b>🧩 Custom Passive Fingerprint Signatures (<code>~/.s1shell/signatures.d/</code>)</b></summary>

Drop any `*.yaml` file into `~/.s1shell/signatures.d/` to extend S1shell's 81 bundled passive rules without editing source code:

```yaml
signatures:
  - vendor: "Internal Corp"
    product: "Custom Edge Gateway"
    category: "waf"
    confidence: "high"
    headers:
      - name: "x-corp-edge"
        pattern: "^edge/([\\d.]+)"
```

</details>

<details>
<summary><b>🧠 Custom Defensive AI Skills (<code>~/.s1shell/skills.d/</code>)</b></summary>

Drop any `*.yaml` file into `~/.s1shell/skills.d/` to add or override S1shell's 10 built-in defensive AI skills (`s1shell ai skills list`):

```yaml
skills:
  - id: "k8s-ingress-review"
    name: "Kubernetes Ingress Hardening Reviewer"
    category: "hardening"
    description: "Reviews ingress TLS, HSTS, and header posture for Kubernetes clusters."
    recommended_modes: ["remediate", "triage"]
    system_prompt: |
      Focus exclusively on defensive Kubernetes Ingress and TLS hardening.
      Cite exact Finding IDs and CVE IDs present in telemetry.
```

</details>

<a id="online-and-local-mcp-server-s1shell-mcp-serve"></a>
<details open>
<summary><b>🌐 Online &amp; Local Read-Only MCP Server (<code>s1shell mcp serve</code> — Streamable HTTP + Stdio, 30–33 Tools)</b></summary>

S1shell runs as a **live online MCP server** (MCP `2025-03-26` + `2024-11-05` compatible) over **Online Streamable HTTP** (`--transport http`) or **Local Stdio** (`--transport stdio`), exposing **30 default online/offline read-only tools**, **4 live MCP Resources**, and **10+ native MCP Prompts** (your defensive AI skills):

#### Start the Online Streamable HTTP MCP Server

```bash
# 1. Start online Streamable HTTP MCP on localhost:8765 with an auto-generated Bearer token
s1shell mcp serve --transport http --host 127.0.0.1 --port 8765 --generate-token

# 2. Or bind on a remote Kali/LAN server (non-loopback bind REQUIRES --token or S1SHELL_MCP_TOKEN)
export S1SHELL_MCP_TOKEN="replace-with-strong-random-token"
s1shell mcp serve --transport http --host 0.0.0.0 --port 8765

# 3. Optional: enable fail-closed guarded target tools (+3 read-only tools: profile, fingerprint, assess)
#    Every target call STILL enforces ~/.s1shell/scope.yaml + IP pinning + SHA-256 audit.log
s1shell mcp serve --transport http --port 8765 --generate-token --allow-scoped-targets --authorized

# 4. Verify your running online MCP server (/healthz + initialize + tools/resources/prompts)
s1shell mcp ping --url http://127.0.0.1:8765/mcp --token "$S1SHELL_MCP_TOKEN"

# 5. Generate ready-to-paste client JSON config (antigravity | claude | cursor | vscode | windsurf | http)
s1shell mcp config antigravity --transport http --url http://127.0.0.1:8765/mcp --token "$S1SHELL_MCP_TOKEN"
```

> [!TIP]
> **Connecting from another machine?** Either put `http://127.0.0.1:8765/mcp` behind a TLS reverse proxy (Caddy/NGINX) or forward safely over SSH: `ssh -L 8765:127.0.0.1:8765 user@kali-box`. Non-loopback `Origin` headers are blocked (`403`) by default to prevent DNS-rebinding attacks; pass `--allow-origin https://your-client.example` when needed.

#### Exposed Online &amp; Local MCP Capabilities

| Group | Mode | Exposed MCP Tools / Resources / Prompts |
| --- | --- | --- |
| **Live Passive Intel &amp; OSINT** | Online (zero target contact) | `s1shell_intel_lookup` (VT, GreyNoise, urlscan.io, RDAP), `s1shell_intel_advisory` (GHSA), `s1shell_intel_ct` (`crt.sh`), `s1shell_intel_rdap` |
| **Live CVE &amp; SBOM Feeds** | Online (zero target contact) | `s1shell_cve_search` (NVD 2.0 + KEV/EPSS), `s1shell_cve_get` (NVD + CVE.org + GHSA), `s1shell_cve_audit` (OSV.dev across 14 lockfile/SBOM formats + `recursive`) |
| **Defensive AI &amp; Skills** | Online / Local Ollama | `s1shell_ai_analyze` (skills, pipelines, NDA redaction on by default, grounding check), `s1shell_ai_skills_list`, `s1shell_ai_prepare_context` |
| **Local Scanners &amp; Deep Analyzers** | Offline *(optional passive DNS for `email`)* | `s1shell_scan_secrets` (27+ redacted secret detectors + git diffs), `s1shell_scan_config` (Docker/K8s/GHA/Compose/NGINX/SSHd/`.env`), `s1shell_scan_sbom` (CycloneDX 1.5), `s1shell_analyze_csp` (CSP3 bypass evaluator), `s1shell_analyze_email` (SPF/DMARC/DKIM), `s1shell_analyze_headers` (offline HTTP posture), `s1shell_analyze_cvss` (CVSS v3.x/v4.0) |
| **Governance, Analysis &amp; Codec** | Online DNS / Offline | `s1shell_doctor`, `s1shell_tor_status`, `s1shell_scope_list`, `s1shell_scope_check`, `s1shell_audit_list`, `s1shell_audit_verify`, `s1shell_fingerprint_from_profile`, `s1shell_assess_diff`, `s1shell_remediate`, `s1shell_codec_decode`, `s1shell_codec_encode`, `s1shell_codec_inspect`, `s1shell_codec_hash` |
| **Scoped Target Tools *(Opt-In)*** | Online *(requires `--allow-scoped-targets --authorized`)* | `s1shell_profile`, `s1shell_fingerprint`, `s1shell_assess` — fail-closed `scope.yaml` + SHA-256 `audit.log` on every call |
| **Native MCP Resources &amp; Prompts** | Built-in | Resources: `s1shell://doctor`, `s1shell://scope`, `s1shell://skills`, `s1shell://audit/recent` · Prompts: all 10 bundled + custom `~/.s1shell/skills.d/*.yaml` skills |

#### Client Configuration Snippets (Online HTTP vs Local Stdio)

**Online Streamable HTTP Client (Antigravity / Cursor / Claude / Generic MCP):**

```json
{
  "mcpServers": {
    "s1shell": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_S1SHELL_MCP_TOKEN"
      }
    }
  }
}
```

**Local Stdio Client (auto-spawned subprocess — still queries live online intel/CVE/AI feeds):**

```json
{
  "mcpServers": {
    "s1shell": {
      "command": "s1shell",
      "args": ["mcp", "serve"]
    }
  }
}
```

</details>

<a id="defensive-tor-routing"></a>
<details>
<summary><b>🧅 Optional Defensive Tor (<code>socks5h://</code>) Routing — Analyst OPSEC &amp; Zero-Leak Target Assessment</b></summary>

S1shell supports fail-closed local Tor (`socks5h://127.0.0.1:9050` / `9150`) with **zero local DNS leaks**, **zero silent clearnet fallback**, and **zero IP rotation/WAF evasion**:

```bash
# 1. Start Tor on Kali Linux & verify readiness (if upgrading an existing pipx install, inject socksio once)
pipx inject s1shell socksio
sudo systemctl enable --now tor
s1shell tor status       # offline check (tor binary, socksio, port 9050/9150)
s1shell tor check        # live exit verification via check.torproject.org/api/ip

# 2. Analyst OPSEC mode (`--tor`): routes passive OSINT, CVE, SBOM, & Cloud AI through Tor
#    (auto-bypasses Tor for local Ollama/MCP; clearnet targets stay direct IP-pinned)
s1shell intel ct target.com --tor
s1shell cve search --keyword "nginx 1.24" --enrich --tor

# 3. Full zero-leak target URL/domain assessment over Tor (`--tor --tor-targets --authorized`)
#    Routes scope DNS & DNS hygiene via DoH-over-Tor, TLS via SOCKS5h tunnel, and single-GET HTTP via socks5h://
s1shell assess https://www.target.com --authorized \
  --tor --tor-targets --enrich-cve --intel --well-known --check-methods \
  --out-dir ./results/target-via-tor

# 4. Direct vs Tor Edge Perspective Diff (detect WAF Tor-exit blocking & split-horizon header leaks)
s1shell assess https://www.target.com --authorized --skip-cve --out-dir ./results/target-direct
s1shell assess https://www.target.com --authorized --tor --tor-targets --skip-cve --out-dir ./results/target-tor
s1shell diff ./results/target-direct/assess.json ./results/target-tor/assess.json

# 5. Authorized Tor v3 `.onion` hidden-service defensive posture audit (zero clearnet DNS)
s1shell scope add <56-char-v3-address>.onion --owner "Org" --ref "SOW-ONION-1" --expires 2026-12-31
s1shell assess http://<56-char-v3-address>.onion --authorized --tor --tor-targets --skip-cve --out-dir ./results/onion
```

> [!NOTE]
> **OPSEC & Scope Notes:** Personal API keys (`NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, etc.) still identify your API account even over Tor, and some Cloudflare-fronted APIs may rate-limit Tor exit nodes. `--tor --tor-targets` strictly permits **public clearnet targets** (or authorized v3 `.onion` hosts) and always blocks private/loopback/CGNAT/metadata IPs.

</details>

---

## Part 2: Pentesting & Assessment Guide (Example: `https://www.target.com`)

```mermaid
flowchart LR
    P1["Phase 1\nPassive OSINT\n(Zero Contact)"] --> P2["Phase 2\nScope Gate\n(Allow/Exclude)"]
    P2 --> P3["Phase 3\nRead-Only Assess\n(target.com)"]
    P3 --> P4["Phase 4\nCVE · SBOM\n& Offline Codec"]
    P4 --> P5["Phase 5\nRemediate · AI\nDiff & Audit"]

    style P1 fill:#0f172a,stroke:#22d3ee,color:#f8fafc
    style P2 fill:#0f172a,stroke:#f59e0b,color:#f8fafc
    style P3 fill:#0f172a,stroke:#38bdf8,color:#f8fafc
    style P4 fill:#0f172a,stroke:#a78bfa,color:#f8fafc
    style P5 fill:#0f172a,stroke:#34d399,color:#f8fafc
```

### ⚡ Quick 4-Command Engagement Flow (TL;DR)

Every authorized target engagement follows the same 4-step loop: **Add Scope → Verify Scope → Assess → Remediate**:

```bash
# 1. Authorize the target in ~/.s1shell/scope.yaml (required before any target packet is sent)
s1shell scope add target.com --include-subdomains \
  --owner "Target Corp" --ref "SOW-2026-014" --expires 2026-12-31

# 2. Verify DNS & scope match (expected output: [IN SCOPE])
s1shell scope check https://www.target.com

# 3. Run the read-only assessment and save HTML / MD / SARIF / JSON reports
s1shell assess https://www.target.com --authorized \
  --enrich-cve --intel --well-known --check-methods \
  --operator "Jane Doe" --out-dir ./results/target-com

# 4. Generate copy-paste server/DNS hardening configs and open report.html
s1shell remediate ./results/target-com/assess.json --stack auto --out ./results/target-com/hardening.md
```

<details>
<summary><b>📺 Example Terminal Output Preview (Posture + Target Identity, Contacts, Emails/Gmail, Phones &amp; Keys/IDs)</b></summary>

```text
[IN SCOPE] target=https://www.target.com resolved_ips=[93.184.216.34] — Authorized by scope entry '7c715dbe' (SOW-2026-014).

Assessment Posture Summary: https://www.target.com/ (93.184.216.34)
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric          ┃ Value                                                      ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Scope Ref       │ SOW-2026-014 (7c715dbe) | preset=web                       │
│ Posture Score   │ 74/100 (Grade C | Risk MEDIUM)                             │
│ Findings        │ CRITICAL=0, HIGH=1, MEDIUM=3, LOW=4, INFO=2                │
│ Detected Stack  │ nginx 1.24.0, Cloudflare, jQuery 3.5.1                     │
│ Correlated CVEs │ 2 (KEV=0, P1-URGENT=1)                                     │
│ Saved Bundle    │ report.html, report.md, report.sarif, assess.json, ...     │
└─────────────────┴────────────────────────────────────────────────────────────┘

Target Identity, Contacts (Email / Gmail / Phone) & Surface Entities: https://www.target.com/
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Category                   ┃ Extracted Values / Details                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Target URL / Host / IP     │ https://www.target.com/ | Pinned IP: 93.184.216.34 │
│ TLS Cert Identity & ID     │ Subject=CN=www.target.com,O=Target Corp |       │
│                            │ Issuer=CN=DigiCert TLS RSA SHA256 |             │
│                            │ Serial=04a1b2c3d4e5f601 | SPKI=base64pin...     │
│ Certificate SANs / Domains │ www.target.com, api.target.com, auth.target.com │
│ Names / Org / Identity     │ Title: Target Online Portal                     │
│                            │ Generator: WordPress 6.5.2                      │
│                            │ meta:author: Juan Dela Cruz                     │
│                            │ jsonld:Organization.name: Target Corp           │
│                            │ jsonld:Organization.taxID: TIN-123-456-789-000  │
│ Emails & Gmail Contacts    │ admin.target@gmail.com [Gmail],                 │
│                            │ security@target.com (security.txt),             │
│                            │ abuse@registrar.example (RDAP)                  │
│ Phone / Contact Numbers    │ +63288881234, +63 917 555 0199, 0918-234-5678   │
│ Keys / Client & App IDs    │ gcp_api_key=AIza****stuv (html)                 │
│                            │ google_analytics_id=G-987654321A (html)         │
│                            │ google_tag_manager_id=GTM-ABC1234 (html)        │
│                            │ firebase_project_id=target-prod-01 (html)       │
│                            │ firebase_app_id=1:123456789012:web:abcdef...    │
│                            │ stripe_publishable_key=pk_live_51H12345678...   │
│                            │ oauth_client_id=target-web-client-prod (html)   │
│ Social & Profile Links     │ https://github.com/target-org                   │
│                            │ https://www.linkedin.com/company/target-org     │
│ Cloud Buckets & API Paths  │ cloud:https://target-assets.s3.amazonaws.com,   │
│                            │ /api/v2/users/profile                           │
│ Forms & Input Parameters   │ POST /auth/login [params: user*, password*,     │
│                            │ redirect_uri*]                                  │
│ Internal IPs & Dev Comments│ comment:TODO: remove staging endpoint,          │
│                            │ internal:10.24.0.15                             │
└────────────────────────────┴─────────────────────────────────────────────────┘
```

</details>

### Command Modes at a Glance

| Mode | Scope & `--authorized` Required? | Commands |
| --- | --- | --- |
| **Zero-Target-Contact (Passive / Offline)** | No — never sends packets to `target.com` | `scan secrets\|config\|sbom`, `analyze csp\|email\|headers\|cvss`, `intel ct\|rdap\|lookup\|advisory`, `cve search\|get\|audit`, `codec decode\|encode\|inspect\|hash`, `fingerprint --from-profile`, `remediate`, `diff`, `report build`, `ai env\|skills\|analyze\|investigate\|chat`, `tor status\|check`, `mcp serve\|config\|ping` *(default)*, `audit`, `doctor` |
| **Authorized Target Mode (Read-Only)** | **Yes** — must match `scope.yaml` + `--authorized` | `assess <target \| --targets-file>`, `profile <target>`, `fingerprint <target>`, `mcp serve --allow-scoped-targets --authorized` *(opt-in)* |
| **Tor Zero-Leak Modes *(Optional)*** | `--tor` (no target scope) · `--tor --tor-targets` (**Yes** + public/v3 `.onion` only) | Add `--tor` for passive OSINT/CVE/SBOM/Cloud AI OPSEC; add `--tor --tor-targets --authorized` to route target DoH DNS, SOCKS5h TLS, & single-GET HTTP through Tor |

> [!TIP]
> **Want to practice safely on localhost first?** Authorize `127.0.0.1` (`s1shell scope add 127.0.0.1 --owner "Lab" --ref "LAB-1" --expires 2027-12-31`) and run `s1shell assess http://127.0.0.1:<port> --authorized --skip-cve --out-dir ./results/lab` against your own local test server.

---

### Phase 1 — Pre-Engagement Passive OSINT (Zero Target Contact)

Gather passive infrastructure, certificate SANs, domain registration, and reputation telemetry before touching `https://www.target.com` (accepts full URLs, subdomains, apex domains, or IPs — automatically falling back from subdomains like `https://m.target.com` or `portal.acme.com.ph` to the registrable apex domain `target.com` / `acme.com.ph`; cached in `~/.s1shell/cache.db` with automatic retry/backoff on HTTP `429`/`502`/`503`/`504`):

```bash
# 1. Enumerate Certificate Transparency SANs passively (zero API key; accepts URL, subdomain, or apex domain)
s1shell intel ct https://www.target.com --export-candidates ./target-candidates.txt

# 2. Inspect domain/IP registration, registrar, emails, phones, & entities via RDAP (zero API key; auto-resolves subdomains to apex)
s1shell intel rdap https://www.target.com
s1shell intel rdap 93.184.216.34

# 3. Query passive VirusTotal, urlscan.io Search, GreyNoise, & RDAP reputation
s1shell intel lookup https://www.target.com --sources vt,urlscan,rdap
s1shell intel lookup 93.184.216.34 --sources vt,greynoise,rdap

# Optional Analyst OPSEC: append `--tor` to route any Phase 1 passive lookup via local Tor SOCKS5h
# s1shell intel ct https://www.target.com --tor
```

---

### Phase 2 — Scope Onboarding & Pre-Flight Gate

> [!TIP]
> **Pre-Configured `.com`, `.ph`, `.com.ph` & Global TLD Scope (`scope.yaml.example`):**
> S1shell ships with [scope.yaml.example](scope.yaml.example) (and auto-discovers project `./scope.yaml` or `~/.s1shell/scope.yaml`) containing **35 pre-configured TLD rules** (`.com`, `.ph`, `.com.ph`, `.gov.ph`, `.edu.ph`, `.org.ph`, `.net.ph`, `.org`, `.net`, `.io`, `.dev`, `.app`, `.co`, `.ai`, `.edu`, `.gov`, regional TLDs, & `127.0.0.1`) while still enforcing deny-first `--exclude` rules, private/CGNAT/metadata anti-SSRF protection, `--authorized` confirmation, and SHA-256 `audit.log`:
>
> ```bash
> cp -n scope.yaml.example scope.yaml && chmod 600 scope.yaml
> mkdir -p -m 700 ~/.s1shell && cp -n scope.yaml.example ~/.s1shell/scope.yaml && chmod 600 ~/.s1shell/scope.yaml
> ```

Onboard specific authorized SOW hosts, leading-dot TLDs (`.com`, `.ph`, `.com.ph`), or deny-first exclusions (`--exclude`), then confirm DNS + scope status before any packet is sent:

```bash
# Add specific authorized domain or leading-dot TLD (supports .com, .ph, .com.ph, *.domain, IP, CIDR, URL prefix, or v3 .onion)
s1shell scope add target.com --include-subdomains \
  --owner "Target Corp" --ref "SOW-2026-014" --expires 2026-12-31 \
  --notes "Q4 authorized web posture assessment"
s1shell scope add .com.ph --owner "Operator" --ref "SOW-PH-2026" --expires 2029-12-31 --replace

# Explicitly exclude out-of-scope subdomains or sensitive IPs (deny-first precedence)
s1shell scope add payments.target.com --exclude \
  --owner "Target Corp" --ref "SOW-2026-014" --expires 2026-12-31

# Pre-flight verification (checks scope.yaml rules + DNS anti-escape without sending HTTP/TLS packets)
s1shell scope check https://www.target.com
s1shell scope check https://payments.target.com   # -> exit 2 (excluded)
```

<details>
<summary><b>📄 Bulk Scope Import for Multi-Host Engagements (<code>scope import --dry-run</code>)</b></summary>

Create a reviewed `target-scope.txt` (`#` for comments, `!` prefix for exclusions):

```text
# Authorized hosts from SOW-2026-014
www.target.com
api.target.com
!payments.target.com
```

Validate with `--dry-run`, then import:

```bash
s1shell scope import target-scope.txt \
  --owner "Target Corp" --ref "SOW-2026-014" --expires 2026-12-31 --dry-run

s1shell scope import target-scope.txt \
  --owner "Target Corp" --ref "SOW-2026-014" --expires 2026-12-31
```

</details>

---

### Phase 3 — Scoped Read-Only Target Assessment (`https://www.target.com`)

#### 3.1 All-in-One Web Assessment

Runs **profile → passive fingerprint & EOL → CPE-verified CVE + KEV/EPSS → passive threat intel → posture scoring (CWE/ASVS/OWASP/NIST) → offline hardening playbook → full report bundle**:

```bash
s1shell assess https://www.target.com --authorized \
  --enrich-cve --intel --well-known --check-methods \
  --operator "Jane Doe" --out-dir ./results/target-com
```

```text
results/target-com/
├── report.html        # Self-contained autoescaped executive & technical HTML report
├── report.md          # Markdown report ready for Jira tickets, wikis, or PRs
├── report.sarif       # SARIF 2.1.0 findings for GitHub Code Scanning / VS Code
├── assess.json        # Master artifact consumed by `remediate`, `diff`, & `ai analyze`
├── profile.json       # Raw DNS, TLS chain, HTTP headers, cookies, well-known, & passive HTML
├── fingerprint.json   # Detected server, CDN, WAF, framework, JS library CPEs, & EOL flags
├── cves.json          # Matched CVEs with KEV, EPSS, GHSA, & SSVC priority tiers
└── intel.json         # Passive VirusTotal, GreyNoise, urlscan.io Search, & RDAP context
```

#### 3.2 API Preset, Multi-Target Batch & Standalone Profiling

```bash
# API preset (suppresses browser HTML/clickjacking noise) with waiver & CI thresholds (exit 4)
s1shell assess https://api.target.com --authorized \
  --preset api --check-methods --ignore-finding DNS-005 \
  --fail-on HIGH --min-score 80 --format sarif --out ./results/api-target.sarif

# Sequential guarded batch assessment (concurrency=1, scope-gated per target, HTML dashboard)
s1shell assess --targets-file target-urls.txt --authorized \
  --delay 0.5 --enrich-cve --intel --fail-on CRITICAL --out-dir ./results/target-batch

# Standalone granular profile + zero-network offline fingerprinting
s1shell profile https://www.target.com --authorized \
  --tls-versions --dns-security --well-known --check-methods \
  --format json --out ./results/profile.json
s1shell fingerprint --from-profile ./results/profile.json \
  --format json --out ./results/fp.json

# Optional zero-leak Tor edge perspective check (compare direct vs Tor exit WAF/header behavior)
s1shell assess https://www.target.com --authorized \
  --tor --tor-targets --skip-cve --out-dir ./results/target-tor
s1shell diff ./results/target-com/assess.json ./results/target-tor/assess.json
```

---

### Phase 4 — CVE Triage, SBOM Auditing & Offline Token/Codec Analysis

All Phase 4 commands are **zero-target-contact** (offline or public vulnerability feeds only).

#### 4.1 Correlate Stack Fingerprints to CVEs, KEV, EPSS & GHSA

```bash
# Correlate detected stack components from Phase 3 with CISA KEV & FIRST EPSS priority tiers
s1shell cve search --from-fingerprint ./results/target-com/fingerprint.json --enrich
s1shell cve search --from-fingerprint ./results/target-com/fingerprint.json --kev-only

# Targeted research by product keyword or specific CVE IDs (NVD + CVE.org + GHSA + KEV/EPSS)
s1shell cve search --keyword "nginx 1.18" --min-cvss 7.0 --enrich
s1shell cve get CVE-2021-23017 CVE-2023-44487 --enrich

# Query GitHub Security Advisories directly
s1shell intel advisory --cve CVE-2023-45803
s1shell intel advisory --ecosystem pip --package requests
```

#### 4.2 Audit Client Repositories, Lockfiles & SBOMs (14 Formats)

Scans `requirements.txt`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pom.xml`, **CycloneDX**, and **SPDX 2.3** SBOMs via **OSV.dev + pure-Python CVSS v3.1 + KEV/EPSS**, generating highest-version semantic upgrade commands:

```bash
s1shell cve audit requirements.txt --enrich --fail-on HIGH
s1shell cve audit ./target-repo --recursive --enrich --format sarif --out ./results/deps.sarif
s1shell cve audit sbom.spdx.json --enrich --kev-only
```

#### 4.3 Local Secret Scanning, IaC/Config Auditing & CycloneDX 1.5 SBOM (`s1shell scan`)

100% offline local repository & CI/CD security scanning with line/column-accurate **SARIF 2.1.0** output and `--fail-on` policy gates (`exit 4`):

```bash
# Scan a repository or staged git changes for exposed credentials (strictly redacted output)
s1shell scan secrets ./target-repo --fail-on HIGH --format sarif --out ./results/secrets.sarif
s1shell scan secrets . --git-staged --fail-on HIGH
s1shell scan secrets . --git-diff main...HEAD

# Audit Dockerfiles, Kubernetes manifests, GitHub Actions, Docker Compose, NGINX, SSHd & .env
s1shell scan config ./target-repo --fail-on HIGH --format sarif --out ./results/iac.sarif

# Generate a CycloneDX 1.5 JSON SBOM from lockfiles/manifests/Dockerfiles and audit via OSV.dev
s1shell scan sbom ./target-repo --raw-bom --out ./results/sbom.cdx.json
s1shell cve audit ./results/sbom.cdx.json --enrich --fail-on HIGH
```

#### 4.4 Deep Offline CSP3, Email Auth, Header & CVSS Analyzers (`s1shell analyze`)

```bash
# Evaluate a Content-Security-Policy for JSONP/CDN script gadgets, duplicates, typos & hardened rewrite
s1shell analyze csp "default-src 'self'; script-src 'unsafe-inline' https://cdn.jsdelivr.net"
s1shell analyze csp --from-profile ./results/target-com/assess.json

# Audit SPF IPv4 CIDR blast radius & lookup budget, DMARC alignment & DKIM DER RSA/Ed25519 key bits
s1shell analyze email target.com --selector google
s1shell analyze email target.com --offline --spf "v=spf1 ip4:10.0.0.0/16 ~all" --dmarc "v=DMARC1; p=none"

# Audit raw HTTP response headers from curl/Burp/DevTools completely offline (scores, fingerprints & fixes)
curl -sI https://www.target.com | s1shell analyze headers - --url https://www.target.com/
s1shell analyze headers --file ./captured-headers.txt --preset strict

# Calculate & decode FIRST CVSS v3.0/v3.1 (Base + Temporal + Environmental) and v4.0 metric vectors
s1shell analyze cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
```

#### 4.5 Offline Decoding, Token/Cert Inspection & Hashing (`s1shell codec`)

```bash
# Magic auto-decode (default `-e auto` peels nested URL -> Base64 -> Gzip -> JSON)
s1shell codec decode "SGVsbG8gUzFzaGVsbCE="
s1shell codec decode "48:65:6c:6c:6f" -e hex --raw
s1shell codec decode "Uryyb" -e caesar --all-shifts
s1shell codec decode "eJz..." --chain url,base64,zlib

# Pipe from stdin (`-`) or encode with chained pipelines
echo "48656c6c6f" | s1shell codec decode - -e hex --raw
s1shell codec encode "Hello S1shell" --chain gzip,base64url --raw

# Smart offline inspector (JWT hygiene, X.509 PEM/DER, hash ID, Unix epoch, entropy, auto-decode)
s1shell codec inspect "5d41402abc4b2a76b9719d911017c592"
s1shell codec inspect --file ./results/target-com/server.pem

# Compute evidence hashes & Shannon entropy
s1shell codec hash --file ./results/target-com/report.html
```

<details>
<summary><b>🔤 Supported Offline Codecs Table (25 Codecs + Magic Auto)</b></summary>

| Codec Group | Supported Names / Aliases | Highlights |
| --- | --- | --- |
| **Base-N** | `base64` (`b64`), `base64url` (`b64url`), `base32` (`b32`), `base58` (`b58`), `base85` (`b85`), `ascii85` (`a85`) | Auto-padding & whitespace-tolerant decoding |
| **Hex & Numeric** | `hex` (`b16`), `hex-escaped`, `binary` (`bin`), `octal` (`oct`), `decimal` (`dec`) | Accepts `0x`, colons `aa:bb`, spaces, & `\x41` |
| **Web & Text** | `url` (`percent`), `url-all`, `html`, `unicode`, `quoted-printable` (`qp`), `punycode` (`idna`) | Multi-layer URL/HTML/Unicode & `xn--` homograph decode |
| **Compression & Auth** | `gzip`, `zlib`, `deflate`, `gzip-b64`, `zlib-b64`, `saml`, `jwt` | 8 MiB zip-bomb cap; SAML XML pretty-print; JWT UTC & hygiene checks |
| **Classic & Magic** | `rot13`, `caesar` (`--shift`, `--all-shifts`), `morse`, `auto` (`--max-depth`) | Recursive magic peeling with step-by-step trace |

</details>

---

<a id="defensive-ai-skills"></a>
### Phase 5 — Remediation Playbooks, Defensive AI Skills, Reporting & Re-Test Drift

<details>
<summary><b>🧠 10 Built-In AI Skills (<code>s1shell ai skills list</code> + custom <code>~/.s1shell/skills.d/*.yaml</code>)</b></summary>

| Skill ID (`--skill`) | Category | Focus |
| --- | --- | --- |
| `attack-path-modeling` | Threat Modeling | Chains observed primitives (keys/IDs, buckets, CNAMEs, form params, JWT/OIDC, EOL/KEV CVEs) into cost-ordered MITRE ATT&CK paths with `Confirmed`/`Likely` confidence & D3FEND counters |
| `ptes-ops-chain` | Pentest Ops | Terse, command-first operator brief mapping recon entities (emails/Gmail, keys/IDs, forms, internal IPs, CT/RDAP) and findings to ATT&CK (`TA0043`/`TA0001`/`TA0006`), OWASP WSTG v4.2, CVSS+EPSS, & D3FEND |
| `pentest-report-writer` | Reporting | Formal pentest findings with Business Impact, Root Cause, Evidence, CVSS/CWE/OWASP/ASVS, and Remediation |
| `threat-intel-correlator` | OSINT | Cross-correlates CT SANs, RDAP, VirusTotal, GreyNoise, urlscan.io, and profile data for shadow assets & drift |
| `sbom-supply-chain` | Supply Chain | Prioritizes OSV.dev lockfile & CycloneDX/SPDX SBOM vulnerabilities via KEV, EPSS, and safe patch groupings |
| `zero-trust-hardening` | Remediation | Generates stack-tailored configs (NGINX, Apache, Caddy, Cloudflare, Express, DNS) fixing TLS/header/cookie gaps |
| `compliance-mapper` | Governance | Maps findings to OWASP Top 10:2021, OWASP ASVS 4.0, CWE, NIST SP 800-53, ISO 27001, & PCI-DSS 4.0 |
| `detection-engineering` | Blue Team | Produces defensive SIEM/Sigma/WAF detection rules & anomaly indicators for observed risks |
| `retest-diff-brief` | Re-Test | Summarizes resolved findings, regressions, and remaining exposure from `s1shell diff` artifacts |
| `token-crypto-auditor` | Crypto / Auth | Audits passively observed JWT hygiene, OIDC/JWKS issues, X.509 chains, SPKI pins, and TLS ciphers |

</details>

```bash
# 1. Deterministic offline hardening snippets (nginx, apache, caddy, express, cloudflare, traefik, dns, security.txt)
s1shell remediate ./results/target-com/assess.json \
  --stack auto --format md --out ./results/target-com/hardening.md

# 2. Advanced defensive AI tactics (10 skills, multi-stage pipelines, reversible NDA redaction, grounding check)
s1shell ai skills list
s1shell ai skills show attack-path-modeling

# Skill-driven analysis with reversible redaction, SQLite cache, & failover
s1shell ai analyze \
  --input ./results/target-com/assess.json \
  --skill attack-path-modeling --redact --restore --cache \
  --fallback builtin --format md --out ./results/target-com/ai_attack_paths.md

# Multi-stage defensive pipeline (deep-triage | purple-team | executive-pack) or validated JSON (--structured)
s1shell ai analyze \
  --input ./results/target-com/assess.json \
  --pipeline purple-team --redact --restore --out ./results/target-com/purple_team.md

s1shell ai analyze \
  --input ./results/target-com/assess.json \
  --skill pentest-report-writer --structured --local-only --provider ollama

# Bounded read-only ReAct investigator (strictly allowlisted to 14 offline/passive tools, max 8 steps)
s1shell ai investigate \
  --input ./results/target-com \
  --goal "Correlate detected EOL/CVE risks with passive RDAP & CT context and prioritize fixes" \
  --max-steps 5 --redact --restore

# Interactive multi-turn defensive copilot (/skill, /skills, /verify, /save, /exit)
s1shell ai chat --input ./results/target-com/assess.json --skill zero-trust-hardening --redact --restore

# 3. Compile custom combined executive HTML report from individual JSON artifacts
s1shell report build \
  --input ./results/target-com/profile.json \
  --input ./results/target-com/fingerprint.json \
  --input ./results/target-com/cves.json \
  --input ./results/target-com/intel.json \
  --operator "Jane Doe" --format html --out ./results/target-com/executive-report.html

# 4. Re-test after client fixes and check for posture regressions (exits 4 on regression)
s1shell assess https://www.target.com --authorized \
  --enrich-cve --intel --well-known --check-methods --out-dir ./results/target-com-retest
s1shell diff \
  ./results/target-com/assess.json \
  ./results/target-com-retest/assess.json \
  --fail-on-regression

# 5. Verify chain-of-custody tamper-evident audit trail
s1shell audit list --category target --target target.com --limit 50
s1shell audit verify
```

---

## Part 3: Reference, CI/CD & Troubleshooting

### CI/CD & GitHub Code Scanning (SARIF 2.1.0)

```yaml
- name: Run S1shell Secret, IaC, Dependency & Authorized Target Gates
  run: |
    s1shell scan secrets . --fail-on HIGH --format sarif --out secrets.sarif
    s1shell scan config . --fail-on HIGH --format sarif --out iac.sarif
    s1shell cve audit requirements.txt --enrich --format sarif --out deps.sarif --fail-on HIGH
    s1shell assess https://www.target.com --authorized \
      --preset api --fail-on HIGH --min-score 80 --format sarif --out target.sarif

- name: Upload SARIF to GitHub Security Tab
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: target.sarif
```

### Quick Troubleshooting

| Symptom / Exit Code | Cause | Fix |
| --- | --- | --- |
| `command not found: s1shell` | CLI not installed via `pipx` yet or shell command cache is stale | Run `pipx install --editable --force .` (or `./scripts/install-kali.sh`), ensure `~/.local/bin` is in `$PATH`, then run `rehash` (`zsh`) / `hash -r` (`bash`). Fallback: `PYTHONPATH=src python3 -m s1shell ...` |
| `exit 2` (`OutOfScopeError`) | Target is not in `scope.yaml`, expired, excluded, or resolves to an un-scoped private/loopback/CGNAT/NAT64/metadata IP | Run `s1shell scope list` and `s1shell scope check https://www.target.com`, then add/renew via `s1shell scope add ... --replace` |
| `exit 3` (`UnauthorizedError`) | Running a target command non-interactively without confirmation | Pass `--authorized` explicitly |
| `exit 4` (`PolicyGateError`) | Findings breached `--fail-on`, `--min-score`, or `--fail-on-regression` | Expected CI/CD gate failure — review findings or adjust thresholds / `--ignore-finding <ID>` |
| Intel/AI feed skipped or rate-limited | Missing or misconfigured API key in `.env` | Run `s1shell doctor` and `s1shell intel env` / `s1shell ai env` to check masked key status |
| `anthropic_api_key: WARN (sk-ant-admin*)` | `.env` contains an Anthropic Admin key instead of an inference key | Replace with a workspace-scoped `sk-ant-api03-*` key, or a user-scoped `sk-ant-usr-*` key + `--workspace-id wrkspc_...`, or use offline `--provider builtin` / `--provider ollama` |
| `Anthropic HTTP 400: not scoped to a workspace` / `credit balance is too low` | `sk-ant-usr-*` key missing `ANTHROPIC_WORKSPACE_ID` or Anthropic Console API billing balance is empty *(separate from claude.ai Pro/Max)* | Set `s1shell ai env --workspace-id wrkspc_...` (using a standard workspace, not the managed Claude Code workspace) and add API credits in Console Plans & Billing, or use `--provider builtin` / `--provider ollama` |
| `Tor SOCKS5h routing requires socksio` | Existing `pipx` venv installed before `httpx[http2,socks]` was added | Run `pipx inject s1shell socksio` (or `pip install 'httpx[http2,socks]'`) and re-check with `s1shell tor status` |
| `Tor SOCKS5h proxy is unreachable (fail-closed)` | Local Tor daemon is stopped (S1shell refuses to silently fall back to clearnet) | Start Tor via `sudo systemctl enable --now tor` (or pass `--tor-proxy socks5h://127.0.0.1:9150` for Tor Browser) and verify with `s1shell tor check` |
| MCP HTTP `401 Unauthorized` or `403 Forbidden Origin` | Missing/wrong Bearer token or un-allowlisted browser `Origin` header | Pass `--token` / set `S1SHELL_MCP_TOKEN`, and pass `--allow-origin https://your-client.example` for web MCP clients |

### Command, Flag & Exit-Code Reference

<details open>
<summary><b>📋 Modules &amp; Commands (18 Modules)</b></summary>

| Command | Network Contact | Purpose |
| --- | --- | --- |
| `s1shell assess <target \| --targets-file>` | Scoped target + NVD/KEV/EPSS (+ optional VT/GN/urlscan/RDAP with `--intel`) | Unified profile, fingerprint, EOL, CVE, intel, posture, playbook, & report bundle |
| `s1shell scan secrets \| config \| sbom` | None (offline) | Local 27+ redacted secret/git-diff scanner, IaC/config auditor (Docker/K8s/GHA/Compose/NGINX/SSHd/`.env`) with line-accurate SARIF 2.1.0, & CycloneDX 1.5 SBOM generator |
| `s1shell analyze csp \| email \| headers \| cvss` | None *(optional passive DNS for `email`)* | CSP3 bypass-gadget evaluator, SPF/DMARC/DKIM key-strength auditor, offline raw HTTP header posture scorer, & FIRST CVSS v3.0/v3.1/v4.0 calculator |
| `s1shell scope add \| import \| list \| check \| remove \| expire` | DNS on `check` only (DoH-over-Tor with `--tor --tor-targets`; zero DNS on `.onion`) | Manage authorized allow/exclude rules (domain, IP, CIDR, URL prefix, v3 `.onion`) & bulk imports |
| `s1shell cve search \| get \| audit \| cache clear` | Public NVD / CVE.org / OSV.dev / GHSA / KEV / EPSS | CVE lookup, SSVC priority triage, & recursive lockfile/SBOM auditing |
| `s1shell intel env \| lookup \| advisory \| ct \| rdap` | Public VT / GreyNoise / urlscan Search / GHSA / crt.sh / RDAP | Zero-target-contact passive threat intel, CT logs, RDAP (org, emails, phones, entities; auto subdomain-to-apex fallback), & `.env` key manager |
| `s1shell codec decode \| encode \| inspect \| hash` | None (offline) | Offline Base64/Hex/URL/SAML/JWT/X.509/Gzip/Auto decoder, encoder, inspector, & hashes |
| `s1shell profile <target>` | Single target (1 GET + TLS + opt-in checks) | Recursive SPF/DNS, TLS chain/Subject/Serial/SPKI, CSP v2, passive emails/Gmail, phones, keys/IDs, names/JSON-LD, social links, cloud buckets, API paths, OIDC/JWKS, `OPTIONS` |
| `s1shell fingerprint [<target> \| --from-profile FILE]` | None (`--from-profile`) or 1 GET | Passive server/CDN/WAF/JS-library identification with CPE 2.3 & 30-product offline EOL flags |
| `s1shell remediate <assess.json>` | None (offline) | Deterministic stack-tailored hardening config generator (`nginx`, `apache`, `caddy`, `express`, `cloudflare`, `traefik`, `dns`, `security.txt`) |
| `s1shell diff <base.json> <curr.json>` | None (offline) | Security posture drift detection & CI regression gate |
| `s1shell report build` | None (offline) | Compile artifacts into JSON, Markdown, SARIF 2.1.0, or HTML |
| `s1shell ai env \| skills \| analyze \| investigate \| chat` | Configured AI endpoint (or offline `builtin` / `--local-only` Ollama) | 10 defensive AI skills, multi-stage pipelines, reversible NDA redaction, grounding checks, 14-tool read-only ReAct investigator & copilot |
| `s1shell audit list \| verify` | None (offline) | Inspect & verify SHA-256 hash chain integrity of `audit.log` |
| `s1shell mcp serve \| config \| ping` | Online HTTP / Stdio (intel + AI; opt-in scoped targets) | Online Streamable HTTP & local stdio MCP server (30–33 tools, Resources, Prompts, Bearer auth, Origin guard), client config generator, & live ping |
| `s1shell tor status \| check` | Offline (`status`) / Tor exit check (`check`) | Check local Tor SOCKS5h readiness or verify live Tor exit egress (fail-closed) |
| `s1shell doctor` / `s1shell --check` / `s1shell help [module] [--all]` | None (offline) | Local environment diagnostics, complete CLI usage guide & module manual |
| `s1shell completion {bash,zsh,fish}` | None (offline) | Shell tab-completion scripts |

</details>

<details>
<summary><b>⚙️ Common Global Flags &amp; Exit Codes</b></summary>

#### Common Global Flags (Accepted Before or After Subcommands)

| Flag | Description |
| --- | --- |
| `--format {table,json,md,html,sarif}` | Output format (`html` on `report build` / `assess`; `sarif` on `report build` / `assess` / `cve audit` / `scan secrets` / `scan config`) |
| `--out FILE` | Write output to `FILE` instead of stdout |
| `--authorized` | Non-interactive authorization confirmation for target-touching commands |
| `--scope-file FILE` | Override path to `scope.yaml` |
| `--home DIR` | Override state directory (default `~/.s1shell` or `$S1SHELL_HOME`) |
| `--tor` | Route passive OSINT, CVE, SBOM, cloud AI, & authorized `.onion` traffic via local Tor `socks5h://` (fail-closed) |
| `--tor-targets` | With `--tor`, also route authorized public target URL/domain checks (DoH DNS, SOCKS5h TLS, single-GET HTTP) over Tor |
| `--tor-proxy URL` | Custom local loopback Tor `socks5h://` proxy URL (default `socks5h://127.0.0.1:9050`) |
| `--no-color` | Disable ANSI colors in terminal tables |
| `--verbose` | Print full tracebacks to stderr on unexpected errors |
| `--check` | Run local readiness diagnostics (`doctor`) + show the complete CLI usage guide |
| `-h`, `--help` / `--help-all` | Show CLI usage guide (`--help`) or complete full manual (`--help-all`) |
| `-V`, `--version` | Show installed `s1shell` version & developer credit (`Dev: Willy Gailo RVS`) |

#### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Validation, network, or runtime error |
| `2` | Target out of scope, excluded, expired, or unsafe IP resolution |
| `3` | Operator authorization not confirmed |
| `4` | CI policy gate threshold breached (`--fail-on`, `--min-score`, `--fail-on-regression`) |

</details>

---

<div align="center">

### Documentation

[Architecture](docs/architecture.md) &nbsp;·&nbsp;
[Artifact & Log Schemas](docs/schemas.md) &nbsp;·&nbsp;
[Changelog](CHANGELOG.md) &nbsp;·&nbsp;
[Contributing](CONTRIBUTING.md) &nbsp;·&nbsp;
[Code of Conduct](CODE_OF_CONDUCT.md) &nbsp;·&nbsp;
[Security Policy](SECURITY.md)

<br />

<sub>Dev: Willy Gailo RVS · Built with care for authorized defensive security assessments · MIT License · <a href="#top">↑ Back to Top</a></sub>

</div>
