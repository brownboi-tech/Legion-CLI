# Security Policy

Legion-CLI is a human-in-the-loop bug bounty automation toolkit for authorized security testing. This project is designed to help researchers organize scope, run approved testing workflows, capture evidence, and draft reports responsibly.

## Supported Use

Legion-CLI should only be used for:

- Assets you own.
- Assets where you have explicit written authorization to test.
- In-scope targets from bug bounty or vulnerability disclosure programs.
- Defensive testing in lab, staging, or internal environments.

Do not use Legion-CLI against systems without permission.

## Safety Model

Legion-CLI separates actions into three levels:

| Level | Behavior |
|---|---|
| `safe` | Low-risk actions that may run after scope validation. |
| `approval` | Noisy or active actions that require user confirmation. |
| `manual` | High-risk actions where Legion provides guidance/checklists only. |

Examples:

- Safe: passive recon, JS analysis, evidence listing, OAuth URL parsing.
- Approval: nuclei scans, ffuf/arjun/dalfox-style active testing, network scans.
- Manual: SQL injection exploitation, command injection testing, request smuggling, SSRF exploitation, race-condition abuse, payment manipulation, and account takeover validation.

## Scope Rules

Before running scans, users should define an allowed scope in `scope.yaml` or `scopes/<program>.yaml`.

Legion-CLI should enforce:

- allowed domains only
- out-of-scope exclusions
- rate-limit awareness
- no destructive testing by default
- approval for noisy or risky actions

If scope is unclear, do not scan.

## Secret Handling

Never commit secrets to this repository.

Do not commit:

- `.env`
- API keys
- OpenAI keys
- session cookies
- authorization headers
- JWTs
- access tokens
- private Burp/Caido exports
- production customer data

Legion-CLI should mask secrets before displaying them in the dashboard or sending data to OpenAI.

Recommended local files that should stay private:

```text
.env
scope.yaml
evidence/
data/
reports/
*.har
*.xml
*.json traffic exports
```

## OpenAI / External API Safety

If `OPENAI_API_KEY` is configured, Legion-CLI may use OpenAI for analysis, summarization, and report drafting.

Before sending data to external APIs, Legion-CLI should mask or remove:

- `Authorization` headers
- cookies
- session IDs
- JWTs
- API keys
- access tokens
- personal or customer-sensitive data

Users are responsible for reviewing data before sharing it with any external service.

## Reporting Vulnerabilities in Legion-CLI

If you find a vulnerability in Legion-CLI itself, please report it responsibly.

Preferred report contents:

- Clear title
- Affected file/module
- Impact
- Reproduction steps
- Proof of concept, if safe
- Suggested fix, if known

Avoid public exploitation details until the issue is fixed.

## Out-of-Scope Reports for This Project

The following are not useful security reports for Legion-CLI:

- Vulnerabilities found on third-party targets using Legion-CLI.
- Issues caused by scanning systems without permission.
- Reports that require destructive testing.
- Exposure of secrets that were intentionally placed in a local `.env` file.
- Dependency warnings without practical exploitability or impact.

## Responsible Researcher Guidelines

When using Legion-CLI:

1. Confirm authorization before testing.
2. Read the target program policy.
3. Respect rate limits.
4. Avoid destructive payloads.
5. Do not access, modify, or delete other users' data.
6. Stop testing if unexpected sensitive data is exposed.
7. Save clean evidence.
8. Report only verified, reproducible issues.

## Legal Notice

Legion-CLI is provided for legitimate security research, education, and defensive testing. Users are responsible for complying with applicable laws, bug bounty program rules, and authorization boundaries.

The maintainers are not responsible for misuse of this tool.
