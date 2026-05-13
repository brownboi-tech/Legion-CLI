# Legion CLI

**Legion CLI** is a human-in-the-loop bug bounty automation system for Parrot OS.

It helps authorized security researchers organize scope, run safe reconnaissance, discover endpoints, inspect JavaScript, classify API attack surface, use an OpenAI-powered reasoning layer, store evidence, and draft clean bug bounty reports.

> Legion suggests. You approve. Nothing high-risk should run blindly.

## Repository description

Human-in-the-loop bug bounty automation CLI for Parrot OS with scope guard, 50-tool registry, AI-assisted triage, evidence storage, and report generation.

## Core architecture

```text
Scope Guard
  -> Tool Registry
  -> Recon / Crawl / JS / API Modules
  -> AI Brain
  -> Human Approval Gate
  -> Evidence Store
  -> Report Generator
```

## Safety model

Legion is designed for authorized testing only.

| Level | Meaning |
|---|---|
| `safe` | Can run automatically when target is in scope |
| `approval` | Command is shown and requires user approval |
| `manual` | Legion prints a checklist; user performs careful manual testing |

## Install

```bash
git clone https://github.com/brownboi-tech/Legion-CLI.git
cd Legion-CLI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install
```

## Quick Start

```bash
python3 main.py tools
python3 main.py recon example.com --scope scope.yaml
python3 main.py js https://example.com --scope scope.yaml
python3 main.py report finding-name --target example.com
```

## Core Modules

- Recon engine
- JS intelligence
- API endpoint classification
- AI reasoning layer
- Human approval system
- Evidence storage
- Markdown report generator
- 50-tool registry

## Supported Tool Groups

- Recon
- Crawling
- JavaScript analysis
- API testing
- Traffic interception
- Mobile reversing
- Cloud/secrets scanning
- Report generation

## Disclaimer

Use only on assets you own or are explicitly authorized to test.
