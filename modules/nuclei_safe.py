from pathlib import Path

from core.runner import run_command, tool_exists, write_output
from modules.evidence_manager import evidence_path, init_evidence_tree
from storage.database import init_db, insert_recon_artifact


def run_nuclei_safe(target: str, urls_file: str) -> dict:
    if not tool_exists('nuclei'):
        return {'target': target, 'error': 'nuclei not installed'}

    init_evidence_tree(target)
    init_db()
    out = evidence_path(target, 'ai-analysis', 'nuclei_safe.txt')

    command = f'nuclei -l {urls_file} -severity low,medium -silent'
    result = run_command(command, risk='approval')
    write_output(str(out), result.get('stdout', ''))
    insert_recon_artifact(target, 'scanner', 'nuclei-safe', str(out), len((result.get('stdout', '') or '').splitlines()))
    return {'target': target, 'output': str(out), 'returncode': result.get('returncode')}
