import os
import shlex
import shutil
import subprocess
from pathlib import Path

from core.approval import require_approval


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: str, risk: str = 'safe', cwd: str | None = None) -> dict:
    if risk != 'safe':
        require_approval(command, risk)

    print(f'[+] Running: {command}')
    proc = subprocess.run(
        shlex.split(command),
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=900,
    )
    return {
        'command': command,
        'returncode': proc.returncode,
        'stdout': proc.stdout,
        'stderr': proc.stderr,
    }


def write_output(path: str, content: str):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content or '')
    print(f'[+] Saved: {output}')
