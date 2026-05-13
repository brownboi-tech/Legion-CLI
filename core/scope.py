import yaml


def validate_scope(target, scope_file):
    with open(scope_file, 'r') as f:
        data = yaml.safe_load(f)

    allowed = data.get('allowed_domains', [])

    if not any(domain in target for domain in allowed):
        raise Exception(f'Target not inside allowed scope: {target}')

    print(f'[+] Scope validated for {target}')
