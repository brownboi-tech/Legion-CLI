# Legion CLI

**Legion CLI** is a human-in-the-loop bug bounty automation CLI for authorized security testing.

It helps you:
- manage scope and safety gates,
- run recon pipelines,
- capture/import traffic,
- analyze JS/API/OAuth/GraphQL surfaces,
- run safe IDOR workflows,
- store artifacts/evidence in SQLite + structured folders,
- draft reports (optionally with OpenAI).

> Legion suggests. You approve. High-risk actions should never run blindly.

---

## Core Architecture

```text
Scope Guard
  -> Tool Registry (50 tools + installed status)
  -> Recon / Traffic / JS / OAuth / GraphQL / IDOR Modules
  -> AI Reasoning Layer (optional)
  -> Human Approval Gate
  -> Evidence + SQLite Storage
  -> Report Builder
```

---

## Safety Model

| Level | Meaning |
|---|---|
| `safe` | Runs automatically for in-scope targets |
| `approval` | Prints command/action and requires user approval |
| `manual` | Legion provides guidance; user performs manually |

---

## Install

```bash
git clone https://github.com/brownboi-tech/Legion-CLI.git
cd Legion-CLI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install
```

---

## Evidence + Storage

### Evidence Tree

```text
evidence/
  <target>/
    requests/
    responses/
    screenshots/
    ai-analysis/
    replay/
```

### SQLite

DB path: `data/legion.db`

Tables include:
- `findings`
- `endpoints`
- `recon_artifacts`
- `endpoint_classifications`
- `auth_diffs`

---

## Key Commands

### Tool Registry

```bash
python3 main.py tools
```

Shows all 50 tools with category, risk level, and installed/missing status.

### Recon

```bash
python3 main.py recon example.com --scope scope.yaml
```

Runs chained recon using available tools (`subfinder`, `httpx`, `katana`, `gau`, `waybackurls`), dedupes endpoints, and stores outputs/artifacts.

### Traffic Capture / Import

```bash
python3 main.py capture-traffic https://example.com
python3 main.py import-traffic burp burp_export.xml --target example.com
python3 main.py import-traffic caido caido_export.json --target example.com
```

### JavaScript Analysis

```bash
python3 main.py js-url example.com --url https://example.com/app.js --scope scope.yaml
python3 main.py js-file example.com --file app.js --scope scope.yaml
python3 main.py js-file example.com --file app.js --ai-summary --scope scope.yaml
```

Extracts routes/endpoints/flags/source maps/cloud URLs/token candidates (masked) and writes `evidence/<target>/ai-analysis/js_findings.json`.

### OAuth / GraphQL

```bash
python3 main.py oauth-check example.com --url "https://idp/authorize?..." --scope scope.yaml
python3 main.py graphql-analyze example.com --endpoint https://example.com/graphql --scope scope.yaml
```

### IDOR Workflows

```bash
python3 main.py idor-plan example.com --replay-file replay.json --scope scope.yaml
python3 main.py idor-test example.com --plan evidence/example.com/ai-analysis/idor_plan.json --user-a-token TOKEN_A --user-b-token TOKEN_B --scope scope.yaml
```

- Generates plan first.
- Replays only safe defaults (`GET`).
- Requires approval before replay actions.

### AI-Assisted Analysis + Reports

```bash
python3 main.py classify-endpoints example.com --input urls.txt --scope scope.yaml
python3 main.py auth-diff example.com --endpoint https://example.com/api/user --unauth-file unauth.txt --auth-file auth.txt --scope scope.yaml
python3 main.py report finding-name --target example.com --ai-draft --evidence-file evidence.txt
python3 main.py report-auto finding-name --target example.com
```

AI features require `OPENAI_API_KEY` and approval before outbound data sharing.

---

## Notes

- Use only with explicit authorization.
- Scope validation is enforced on high-value analysis commands.
- Secrets found in JS analysis are masked before output.

## License

MIT

---

## First Run Test (Parrot OS)

Run these exact commands in order:

```bash
cd Legion-CLI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install

# compile check
python3 -m py_compile main.py core/*.py ai/*.py modules/*.py storage/*.py traffic/*.py browser/*.py

# quick CLI checks
python3 main.py --help
python3 main.py tools

# optional smoke tests
python3 -m pytest -q tests
```

Expected:
- `py_compile` exits with code `0`
- `main.py --help` prints command list
- `main.py tools` prints installed/missing tools
- pytest smoke tests pass (or report missing pytest package)

## Dashboard + Agent Mode

```bash
pip install -r requirements.txt
cp .env.example .env
cp scope.example.yaml scope.yaml
python3 main.py dashboard --host 127.0.0.1 --port 8080
```

Open:

```bash
open http://127.0.0.1:8080
```

## Creating Scope From Program Text

### Dashboard flow
1. Open Dashboard (`python3 main.py dashboard --host 127.0.0.1 --port 8080`).
2. Fill **Program name**.
3. Paste scope/rules into the large scope text box.
4. Click **Create Scope From Chat**.
5. Review JSON preview in results panel.

### CLI flow
```bash
python3 main.py scope-from-text program-name --file scope_text.txt
```

This creates:
- `scopes/program-name.yaml`

## Advanced Security Workflows

Generate stronger test plans (saved in `evidence/<target>/ai-analysis/`):

```bash
python3 main.py security-workflow <target> --type race --scope scope.yaml
python3 main.py security-workflow <target> --type payment --scope scope.yaml
python3 main.py security-workflow <target> --type ssrf --scope scope.yaml
python3 main.py security-workflow <target> --type smuggling --scope scope.yaml
python3 main.py security-workflow <target> --type mobile --scope scope.yaml
python3 main.py security-workflow <target> --type cloud --scope scope.yaml
python3 main.py security-workflow <target> --type business --scope scope.yaml
```

These produce structured, high-value workflow plans for:
- race conditions
- payment logic abuse
- SSRF chain analysis
- request smuggling
- mobile reversing
- cloud misconfiguration/exploitation checks
- complex business logic workflows
