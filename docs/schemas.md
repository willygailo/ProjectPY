# S1shell Canonical Artifact & Log Schemas (`schema_version: "1.0"`, `v0.5.0`)

All JSON outputs emitted with `--format json` include:
- `schema_version`: `"1.0"`
- `tool_version`: S1shell package version (`"0.5.0"`)
- `generated_at_utc`: ISO-8601 UTC timestamp (`Z`)
- `artifact_type`:
  - `"cve_report"` (`s1shell cve search|get`)
  - `"dependency_audit_report"` (`s1shell cve audit`)
  - `"intel_report"` (`s1shell intel lookup`)
  - `"ghsa_report"` (`s1shell intel advisory`)
  - `"ct_report"` (`s1shell intel ct`)
  - `"rdap_report"` (`s1shell intel rdap`)
  - `"intel_env_status"` (`s1shell intel env`)
  - `"codec_transform"` (`s1shell codec decode|encode`)
  - `"codec_inspect"` (`s1shell codec inspect`)
  - `"codec_hash"` (`s1shell codec hash`)
  - `"profile_report"` (`s1shell profile`)
  - `"fingerprint_report"` (`s1shell fingerprint`)
  - `"assess_report"` (`s1shell assess`)
  - `"batch_assess_report"` (`s1shell assess --targets-file`)
  - `"assess_diff_report"` (`s1shell diff`)
  - `"remediation_plan"` (`s1shell remediate`)
  - `"assessment_report"` (`s1shell report build`)
  - `"audit_verify_report"` (`s1shell audit verify`)
  - `"doctor_report"` (`s1shell doctor`)
  - `"ai_env_status"` (`s1shell ai env`)
  - `"ai_analysis_report"` (`s1shell ai analyze [--skill] [--pipeline] [--structured]`)
  - `"ai_skills_catalog"` / `"ai_skill"` (`s1shell ai skills list|show`)
  - `"ai_investigation_report"` (`s1shell ai investigate`)
  - `"ai_prepared_context"` (`s1shell_ai_prepare_context` MCP tool)
  - `"mcp_ping_report"` (`s1shell mcp ping`)
  - `"tor_status_report"` / `"tor_check_report"` (`s1shell tor status|check`)

## 1. Scope File (`~/.s1shell/scope.yaml` or project `./scope.yaml`)

S1shell resolves `scope.yaml` in order: `--scope-file FILE` → `~/.s1shell/scope.yaml` → project `./scope.yaml` (see [scope.yaml.example](../scope.yaml.example) pre-populated with `.com`, `.ph`, `.com.ph`, `.gov.ph`, `.edu.ph`, `.org.ph`, `.net.ph`, global TLDs, and `127.0.0.1`).

```yaml
version: 1
entries:
  - id: "3755fdd3"
    target: "com"
    type: "domain"           # domain | ip | cidr | url_prefix | onion (56-char Tor v3)
    include_subdomains: true # matches *.com (added via `s1shell scope add .com ...`)
    owner: "Operator"
    auth_ref: "SOW-GLOBAL-2026"
    created_at: "2026-11-20T15:18:03Z"
    expires_at: "2029-12-31"
  - id: "f8462c3a"
    target: "ph"
    type: "domain"
    include_subdomains: true # matches *.ph, *.com.ph, *.gov.ph, *.edu.ph, *.org.ph, *.net.ph
    owner: "Operator"
    auth_ref: "SOW-GLOBAL-2026"
    created_at: "2026-11-20T15:18:03Z"
    expires_at: "2029-12-31"
  - id: "acme0002"
    target: "payments.target.com"
    type: "domain"
    include_subdomains: false
    owner: "Target Corp"
    auth_ref: "SOW-2026-014"
    created_at: "2026-11-20T04:00:00Z"
    expires_at: "2029-12-31"
    exclude: true            # deny-first exclusion overrides broader allow rules
```

## 2. Hash-Chained Audit Log (`~/.s1shell/audit.log`, JSON Lines)

Each line is one canonical JSON object chained via SHA-256 (`prev_hash` -> `entry_hash`):

```json
{"timestamp_utc":"2026-11-20T04:00:00Z","category":"target","command":"profile","target":"https://www.target.com","resolved_ips":["93.184.216.34"],"scope_id":"3755fdd3","auth_ref":"SOW-GLOBAL-2026","authorized_via":"flag","outcome":"success","exit_code":0,"duration_ms":145,"error":null,"prev_hash":"GENESIS","entry_hash":"..."}
```

## 3. Assessment Findings & Compliance Tags (`assess_report`)

Each entry in `findings[]` contains `id`, `severity`, `category`, `title`, `evidence`, `remediation`, and structured compliance mappings (`cwe`, `asvs`, `owasp`, `nist`), which are also emitted as SARIF 2.1.0 rule tags under `--format sarif`.

## 4. Inter-Module Pipeline (`v0.5.0`)

- `s1shell scope add .com --owner "Operator" --ref "SOW-2026" --expires 2029-12-31`
- `s1shell scope add .ph --owner "Operator" --ref "SOW-2026" --expires 2029-12-31`
- `s1shell assess https://www.target.com --authorized --enrich-cve --intel --well-known --check-methods --out-dir ./out`
- `s1shell assess https://www.target.com --authorized --tor --tor-targets --skip-cve --out-dir ./out-tor`
- `s1shell diff ./out/assess.json ./out-tor/assess.json`
- `s1shell ai analyze --input ./out/assess.json --skill attack-path-modeling --redact --restore`
- `s1shell ai investigate --input ./out --goal "Prioritize EOL and CVE remediation" --max-steps 5 --redact --restore`
- `s1shell remediate ./out/assess.json --stack auto --format md`
- `s1shell cve audit ./repo --recursive --enrich --format sarif --out deps.sarif`
- `s1shell mcp serve --transport http --host 127.0.0.1 --port 8765 --generate-token`
- `s1shell audit verify`
