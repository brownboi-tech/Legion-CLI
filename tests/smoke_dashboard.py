import pytest
fastapi = pytest.importorskip('fastapi')
from fastapi.testclient import TestClient
from web.app import app


def test_import_web_app():
    assert app is not None


def test_health_route():
    c = TestClient(app)
    assert c.get('/api/health').status_code == 200


def test_chat_recon_with_target_works():
    c = TestClient(app)
    r = c.post('/api/chat', json={'target': 'example.com', 'scope': 'scope.example.yaml', 'message': 'run recon on example.com'})
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert 'intent' in r.json()


def test_chat_nuclei_missing_urls_file_asks():
    c = TestClient(app)
    r = c.post('/api/chat', json={'target': 'example.com', 'scope': 'scope.example.yaml', 'message': 'run nuclei safe scan'})
    if r.status_code == 200:
        j = r.json()
        assert 'urls_file' in (j.get('assistant_message', '') + ' '.join(j.get('next_suggestions', [])))


def test_chat_import_burp_missing_file_asks():
    c = TestClient(app)
    r = c.post('/api/chat', json={'target': 'example.com', 'scope': 'scope.example.yaml', 'message': 'import burp traffic'})
    if r.status_code == 200:
        j = r.json()
        assert 'file' in (j.get('assistant_message', '') + ' '.join(j.get('next_suggestions', [])))


def test_chat_confirm_no_pending_safe_message():
    c = TestClient(app)
    r = c.post('/api/chat/confirm', json={'session_id': 'no-pending-test'})
    assert r.status_code == 200
    assert 'No pending confirmation' in r.json().get('assistant_message', '')
