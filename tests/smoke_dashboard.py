import pytest

fastapi = pytest.importorskip('fastapi')
from fastapi.testclient import TestClient

from web.agent import parse_command
from web.app import app


def test_import_web_app():
    assert app is not None


def test_health_route():
    c = TestClient(app)
    r = c.get('/api/health')
    assert r.status_code == 200
    assert r.json().get('status') == 'ok'


def test_agent_parse():
    out = parse_command('run recon on example.com')
    assert out.get('action') == 'recon-pipeline'


def test_dashboard_command_exists():
    import subprocess, sys
    r = subprocess.run([sys.executable, 'main.py', '--help'], capture_output=True, text=True)
    assert 'dashboard' in r.stdout
