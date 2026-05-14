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


def test_scope_from_chat_endpoint():
    c = TestClient(app)
    payload = {'program': 'demo-program', 'message': 'In scope: example.com Out of scope: admin.example.com'}
    r = c.post('/api/scope/from-chat', json=payload)
    assert r.status_code == 200
    j = r.json()
    assert 'scope_file' in j and 'allowed_domains' in j


def test_agent_parse_shape():
    out = parse_command('run recon on example.com')
    assert out.get('parsed_action') == 'recon-pipeline'


def test_dashboard_command_exists():
    import subprocess, sys
    r = subprocess.run([sys.executable, 'main.py', '--help'], capture_output=True, text=True)
    assert 'dashboard' in r.stdout and 'scope-from-text' in r.stdout
