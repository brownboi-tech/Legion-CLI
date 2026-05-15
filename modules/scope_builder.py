import re
from pathlib import Path
import yaml
import os
from openai import OpenAI

DOMAIN_RE = re.compile(r'(?:(?:https?://)?)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')


def _fallback_extract(message: str) -> dict:
    domains = sorted(set(d.lower().strip('.') for d in DOMAIN_RE.findall(message)))
    out_scope = [d for d in domains if any(k in d for k in ['admin', 'internal', 'staging'])]
    allowed = [d for d in domains if d not in out_scope]
    rules = ['respect rate limits', 'test only listed in-scope assets']
    notes = [message[:500]] if message else []
    return {
        'allowed_domains': allowed,
        'out_of_scope': out_scope,
        'rules': rules,
        'notes': notes,
        'rate_limit_per_minute': 60,
    }


def _ai_extract(message: str) -> dict:
    client = OpenAI()
    prompt = (
        'Extract bug bounty scope into JSON with keys: allowed_domains,out_of_scope,rules,notes,rate_limit_per_minute. '
        'Return strict JSON only.\n\n'+message[:12000]
    )
    resp = client.responses.create(model='gpt-4.1-mini', input=prompt)
    import json
    try:
        data = json.loads(resp.output_text)
    except Exception:
        data = _fallback_extract(message)
    data.setdefault('rate_limit_per_minute', 60)
    return data


def create_scope_from_text(program: str, message: str, save: bool = True) -> dict:
    data = _ai_extract(message) if os.getenv('OPENAI_API_KEY') else _fallback_extract(message)
    scope_dir = Path('scopes')
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_file = scope_dir / f'{program}.yaml'
    if save:
        scope_file.write_text(yaml.safe_dump(data, sort_keys=False))
    return {'scope_file': str(scope_file), **data}


def create_scope_from_file(program: str, file_path: str) -> dict:
    msg = Path(file_path).read_text(errors='ignore')
    return create_scope_from_text(program, msg, save=True)
