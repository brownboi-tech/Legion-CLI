from pathlib import Path


def create_report(finding, target):
    report_dir = Path('reports') / target
    report_dir.mkdir(parents=True, exist_ok=True)

    report_file = report_dir / f'{finding}.md'

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
