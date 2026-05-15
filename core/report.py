from pathlib import Path

from ai.reasoner import draft_report_with_ai


def _collect_evidence_text(target: str) -> str:
    root = Path('evidence') / target
    if not root.exists():
        return ''
    chunks = []
    for p in root.rglob('*'):
        if p.is_file() and p.suffix in {'.txt', '.json', '.md'}:
            chunks.append(f'## {p}\n{p.read_text(errors="ignore")[:2000]}')
    return '\n\n'.join(chunks)


def create_report(finding, target, ai_draft: bool = False, evidence: str = ''):
    report_dir = Path('reports') / target
    report_dir.mkdir(parents=True, exist_ok=True)

    report_file = report_dir / f'{finding}.md'

    if ai_draft:
        content = draft_report_with_ai(finding=finding, target=target, evidence=evidence)
    else:
        content = f'''# {finding}

## Target
{target}

## Summary
Describe the issue.

## Steps to Reproduce
1. Step one
2. Step two

## Impact
Describe impact.

## Evidence
Add requests, responses, screenshots.
'''

    report_file.write_text(content)
    print(f'[+] Report created: {report_file}')


def create_report_from_evidence(finding: str, target: str) -> str:
    evidence = _collect_evidence_text(target)
    create_report(finding=finding, target=target, ai_draft=True, evidence=evidence)
    return str(Path('reports') / target / f'{finding}.md')
