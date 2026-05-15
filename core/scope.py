from pathlib import Path

import yaml


def validate_scope(target, scope_file):
    scope_path = Path(scope_file)
    if not scope_path.exists():
        raise FileNotFoundError(f'Scope file not found: {scope_file}')

    data = yaml.safe_load(scope_path.read_text()) or {}
    allowed = data.get('allowed_domains', [])
    if not isinstance(allowed, list):
        raise ValueError('Invalid scope file format: allowed_domains must be a list')

    if not any(domain in target for domain in allowed):
        raise Exception(f'Target not inside allowed scope: {target}')

    print(f'[+] Scope validated for {target}')
