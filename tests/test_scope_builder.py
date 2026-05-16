from pathlib import Path

import yaml

from core.scope import validate_scope
from modules.scope_builder import normalize_domain, extract_scope_from_text, save_scope, use_scope


def test_normalize_domain_from_url():
    assert normalize_domain('https://example.com/path') == 'example.com'


def test_extract_domains_from_text_fallback():
    out = extract_scope_from_text('demo', 'In scope: https://api.example.com/v1 and *.example.org')
    assert 'api.example.com' in out['allowed_domains']
    assert 'example.org' in out['allowed_domains']


def test_wildcard_scope_matching(tmp_path):
    scope_file = tmp_path / 'scope.yaml'
    scope_file.write_text(yaml.safe_dump({'allowed_domains': ['*.example.com'], 'out_of_scope': []}))
    validate_scope('api.example.com', str(scope_file))


def test_scope_use_copies_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path('scopes').mkdir()
    Path('scopes/demo.yaml').write_text('allowed_domains:\n  - example.com\nout_of_scope: []\n')
    use_scope('demo')
    assert Path('scope.yaml').exists()


def test_validate_scope_accepts_https_target(tmp_path):
    scope_file = tmp_path / 'scope.yaml'
    scope_file.write_text(yaml.safe_dump({'allowed_domains': ['example.com'], 'out_of_scope': []}))
    validate_scope('https://example.com/path', str(scope_file))
