from pathlib import Path

import yaml

from modules.scope_builder import normalize_domain


def _match_allowed(target: str, allowed: str) -> bool:
    t = normalize_domain(target)
    a = (allowed or '').strip().lower()
    if a.startswith('*.'):
        base = normalize_domain(a)
        return t.endswith(f'.{base}') and t != base
    a_norm = normalize_domain(a)
    return t == a_norm or t.endswith(f'.{a_norm}')


def validate_scope(target, scope_file):
    scope_path = Path(scope_file)
    if not scope_path.exists():
        raise FileNotFoundError(f'Scope file not found: {scope_file}')

    data = yaml.safe_load(scope_path.read_text()) or {}
    allowed = data.get('allowed_domains', [])
    out = data.get('out_of_scope', [])
    if not isinstance(allowed, list):
        raise ValueError('Invalid scope file format: allowed_domains must be a list')

    target_norm = normalize_domain(target)
    if not target_norm:
        raise ValueError(f'Invalid target: {target}')

    if any(_match_allowed(target_norm, item) for item in out):
        raise ValueError(f'Target is explicitly out-of-scope: {target} ({target_norm})')

    if not any(_match_allowed(target_norm, item) for item in allowed):
        raise ValueError(
            f'Target not inside allowed scope: {target} ({target_norm}). '
            f'Allowed domains: {allowed}'
        )

    print(f'[+] Scope validated for {target_norm}')
