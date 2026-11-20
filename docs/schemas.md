# S1shell Canonical Artifact & Log Schemas (`schema_version: "1.0"`)

All JSON outputs emitted with `--format json` include:
- `schema_version`: `"1.0"`
- `tool_version`: S1shell package version
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
  - `"ai_analysis"` (`s1shell ai analyze [--skill] [--pipeline] [--structured]`)
  - `"ai_skills_catalog"` / `"ai_skill"` (`s1shell ai skills list|show`)
  - `"ai_investigation_report"` (`s1shell ai investigate`)
  - `"ai_prepared_context"` (`s1shell_ai_prepare_context` MCP tool)
  - `"mcp_ping_report"` (`s1shell mcp ping`)

## 1. Scope File (`~/.s1shell/scope.yaml`)

```yaml
version: 1
entries:
  - id: "acme0001"
    target: "example.com"
    type: "domain"           # domain | ip | cidr | url_prefix
    include_subdomains: true
    owner: "ACME IT"
    auth_ref: "SOW-2026-014"
    created_at: "2026-11-18T12:00:00Z"
    expires_at: "2026-12-31"
  - id: "acme0002"
    target: "billing.example.com"
    type: "domain"
    include_subdomains: false
    owner: "ACME IT"
    auth_ref: "SOW-2026-014"
    created_at: "2026-11-20T04:00:00Z"
    expires_at: "2026-12-31"
    exclude: true
```

## 2. Hash-Chained Audit Log (`~/.s1shell/audit.log`, JSON Lines)

Each line is one canonical JSON object chained via SHA-256 (`prev_hash` -> `entry_hash`):

```json
{"timestamp_utc":"2026-11-20T04:00:00Z","category":"target","command":"profile","target":"https://app.example.com","resolved_ips":["93.184.216.34"],"scope_id":"acme0001","auth_ref":"SOW-2026-014","authorized_via":"flag","outcome":"success","exit_code":0,"duration_ms":145,"error":null,"prev_hash":"GENESIS","entry_hash":"..."}
```

## 3. Assessment Findings & Compliance Tags (`assess_report`)

Each entry in `findings[]` contains `id`, `severity`, `category`, `title`, `evidence`, `remediation`, and structured compliance mappings (`cwe`, `asvs`, `owasp`, `nist`), which are also emitted as SARIF 2.1.0 rule tags under `--format sarif`.

## 4. Inter-Module Pipeline

- `s1shell scope import targets.txt --owner "ACME" --ref "SOW-2026-014" --expires 2026-12-31`
- `s1shell assess https://app.example.com --authorized --enrich-cve --well-known --check-methods --out-dir ./out`
- `s1shell remediate ./out/assess.json --stack auto --format md`
- `s1shell diff ./baseline/assess.json ./out/assess.json --fail-on-regression`
- `s1shell cve audit requirements.txt --enrich --format sarif --out deps.sarif`
- `s1shell audit verify`
