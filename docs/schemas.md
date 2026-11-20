# S1shell Canonical Artifact & Log Schemas (`schema_version: "1.0"`)

All JSON outputs emitted with `--format json` include:
- `schema_version`: `"1.0"`
- `tool_version`: S1shell package version
- `generated_at_utc`: ISO-8601 UTC timestamp (`Z`)
- `artifact_type`: `"cve_report"` | `"profile_report"` | `"fingerprint_report"` | `"assessment_report"` | `"doctor_report"`

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
```

## 2. Audit Log (`~/.s1shell/audit.log`, JSON Lines)

Each line is one JSON object:

```json
{"timestamp_utc":"2026-11-18T12:00:00Z","category":"target","command":"profile","target":"https://app.example.com","resolved_ips":["93.184.216.34"],"scope_id":"acme0001","auth_ref":"SOW-2026-014","authorized_via":"flag","outcome":"success","exit_code":0,"duration_ms":145,"error":null}
```

## 3. Passive Fingerprint Matches (`fingerprint_report`)

Each entry in `matches[]` includes `vendor`, `product`, `category`, `confidence`, optional `version` (extracted passively from matched header banners when present), and `evidence[]`.

## 4. Inter-Module Pipeline

- `s1shell profile <target> --authorized --format json --out profile.json`
- `s1shell fingerprint --from-profile profile.json --format json --out fp.json`
- `s1shell cve search --from-fingerprint fp.json --min-cvss 7.0 --format json --out cves.json`
- `s1shell report build --input profile.json --input fp.json --input cves.json --format html --out report.html`
