import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cmd(args):
    return subprocess.run([sys.executable, 'main.py', *args], cwd=ROOT, capture_output=True, text=True)


def test_help_runs():
    r = run_cmd(['--help'])
    assert r.returncode == 0
    assert 'Legion CLI' in r.stdout


def test_tools_runs():
    r = run_cmd(['tools'])
    assert r.returncode == 0
    assert 'Tool Registry' in r.stdout


def test_scope_file_missing_is_handled():
    r = run_cmd(['recon', 'example.com', '--scope', 'missing-scope.yaml'])
    assert r.returncode != 0
    assert 'Scope file not found' in (r.stdout + r.stderr)


def test_security_workflow_command_exists():
    r = run_cmd(['--help'])
    assert 'security-workflow' in r.stdout


def test_rank_findings_command_exists():
    r = run_cmd(['--help'])
    assert 'rank-findings' in r.stdout


def test_scope_management_commands_exist():
    r = run_cmd(['--help'])
    assert 'scope-use' in r.stdout
    assert 'scope-list' in r.stdout
    assert 'scope-show' in r.stdout
