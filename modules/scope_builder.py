import json
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

import yaml
from openai import OpenAI

DOMAIN_TOKEN_RE = re.compile(r"(?:https?://)?(?:\*\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[\w\-./?%&=+#:]*)?")


def normalize_domain(value: str) -> str:
    text = (value or '').strip().lower()
    if not text:
        return ''
    if text.startswith('*.'):
        text = text[2:]
    if '://' not in text:
        parsed = urlparse(f'https://{text}')
    else:
        parsed = urlparse(text)
    host = parsed.netloc or parsed.path.split('/')[0]
    host = host.split('@')[-1].split(':')[0].strip('.').lower()
    if host.startswith('*.'):
        host = host[2:]
    return host


def _extract_candidates(text: str) -> list[str]:
    return DOMAIN_TOKEN_RE.findall(text or '')


def _fallback_extract(program: str, text: str) -> dict:
    allowed_domains, out_of_scope, rules, notes = [], [], [], []
    wildcard_notes = []
    lower = (text or '').lower()
    for token in _extract_candidates(text):
        d = normalize_domain(token)
        if not d:
            continue
        if token.strip().startswith('*.'):
            wildcard_notes.append(f'wildcard in source text: {token.strip()}')
        line = token.lower()
        if any(k in line for k in ['out of scope', 'out-of-scope']):
            out_of_scope.append(d)
        elif any(k in lower for k in [f'out of scope: {d}', f'out-of-scope: {d}']):
            out_of_scope.append(d)
        else:
            allowed_domains.append(d)
    for ln in (text or '').splitlines():
        ll = ln.strip().lower()
        if not ll:
            continue
        if 'rate limit' in ll and not any(c.isalpha() for c in ll.replace('rate limit', '')):
            pass
        if any(k in ll for k in ['no ', 'do not ', 'must ', 'only ', 'forbidden', 'prohibited', 'respect']):
            rules.append(ln.strip())
    rl = 60
    rate_match = re.search(r'(\d+)\s*(?:requests?|reqs?)\s*(?:/|per)\s*(?:minute|min)', lower)
    if rate_match:
        rl = int(rate_match.group(1))
    notes = ['pasted scope converted by Legion Agent', *wildcard_notes]
    allowed = sorted(set(allowed_domains) - set(out_of_scope))
    out = sorted(set(out_of_scope))
    return {
        'program_name': program,
        'description': f'Auto-extracted scope for {program}',
        'allowed_domains': allowed,
        'out_of_scope': out,
        'rules': sorted(set(rules)) or ['respect rate limits'],
        'notes': notes,
        'rate_limit_per_minute': rl,
    }


def _ai_extract(program: str, text: str) -> dict:
    client = OpenAI()
    prompt = (
        'Extract bug bounty scope into strict JSON only with keys '
        'program_name,description,allowed_domains,out_of_scope,rules,notes,rate_limit_per_minute. '
        'Only include domains/assets explicitly present in text. Do not invent targets. '
        'Normalize domains/URLs to hostnames only.\n\n'
        f'Program: {program}\n'
        f'Text:\n{text[:14000]}'
    )
    resp = client.responses.create(model='gpt-4.1-mini', input=prompt)
    parsed = json.loads(resp.output_text)
    return parsed if isinstance(parsed, dict) else _fallback_extract(program, text)


def extract_scope_from_text(program: str, text: str) -> dict:
    data = _ai_extract(program, text) if os.getenv('OPENAI_API_KEY') else _fallback_extract(program, text)
    data['program_name'] = data.get('program_name') or program
    data['description'] = data.get('description') or f'Auto-extracted scope for {program}'
    data['allowed_domains'] = sorted(set(normalize_domain(x) for x in data.get('allowed_domains', []) if normalize_domain(x)))
    data['out_of_scope'] = sorted(set(normalize_domain(x) for x in data.get('out_of_scope', []) if normalize_domain(x)))
    data['allowed_domains'] = [x for x in data['allowed_domains'] if x not in set(data['out_of_scope'])]
    data['rules'] = [str(x).strip() for x in data.get('rules', []) if str(x).strip()]
    data['notes'] = [str(x).strip() for x in data.get('notes', []) if str(x).strip()]
    data['rate_limit_per_minute'] = int(data.get('rate_limit_per_minute') or 60)
    return data


def save_scope(program: str, scope_data: dict) -> str:
    scope_dir = Path('scopes')
    scope_dir.mkdir(parents=True, exist_ok=True)
    out = scope_dir / f'{program}.yaml'
    payload = {
        'program': scope_data.get('program_name', program),
        'description': scope_data.get('description', ''),
        'allowed_domains': scope_data.get('allowed_domains', []),
        'out_of_scope': scope_data.get('out_of_scope', []),
        'rules': scope_data.get('rules', []),
        'notes': scope_data.get('notes', ['pasted scope converted by Legion Agent']),
        'rate_limit_per_minute': scope_data.get('rate_limit_per_minute', 60),
    }
    out.write_text(yaml.safe_dump(payload, sort_keys=False), encoding='utf-8')
    return str(out)


def use_scope(program: str) -> str:
    source = Path('scopes') / f'{program}.yaml'
    if not source.exists():
        raise FileNotFoundError(f'Scope file not found: {source}')
    shutil.copyfile(source, Path('scope.yaml'))
    return 'scope.yaml'


def list_scopes() -> list[str]:
    scope_dir = Path('scopes')
    if not scope_dir.exists():
        return []
    return sorted(p.stem for p in scope_dir.glob('*.yaml'))


def show_scope(program: str) -> dict:
    path = Path('scopes') / f'{program}.yaml'
    if not path.exists():
        raise FileNotFoundError(f'Scope file not found: {path}')
    return yaml.safe_load(path.read_text(encoding='utf-8')) or {}


def create_scope_from_text(program: str, text: str, save: bool = True, use_active: bool = False) -> dict:
    data = extract_scope_from_text(program, text)
    scope_file = None
    if save:
        scope_file = save_scope(program, data)
    if use_active and scope_file:
        use_scope(program)
    return {'program': program, 'scope_file': scope_file, 'active_scope': 'scope.yaml' if use_active else None, **data}


def create_scope_from_file(program: str, file_path: str) -> dict:
    return create_scope_from_text(program, Path(file_path).read_text(errors='ignore'), save=True)
