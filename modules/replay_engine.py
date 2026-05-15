import json
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

import requests

from core.approval import require_approval
from modules.evidence_manager import evidence_path, init_evidence_tree

SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}
SENSITIVE_FIELDS = {'email', 'phone', 'address', 'user_id', 'role', 'token'}


@dataclass
class SessionProfile:
    name: str
    headers: dict
    cookies: dict


def load_session_profile(name: str, file_path: str) -> SessionProfile:
    data = json.loads(Path(file_path).read_text())
    return SessionProfile(
        name=name,
        headers=data.get('headers', {}) if isinstance(data, dict) else {},
        cookies=data.get('cookies', {}) if isinstance(data, dict) else {},
    )


def _json_keys(text: str) -> set[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return set()
    keys = set()
    if isinstance(obj, dict):
        stack = [obj]
        while stack:
            cur = stack.pop()
            for k, v in cur.items():
                keys.add(str(k))
                if isinstance(v, dict):
                    stack.append(v)
    return keys


def _extract_sensitive(text: str) -> dict:
    try:
        obj = json.loads(text)
    except Exception:
        return {}
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in SENSITIVE_FIELDS:
                out[k] = v
    return out


def _similarity(a: str, b: str) -> float:
    return round(SequenceMatcher(None, a or '', b or '').ratio(), 4)


def replay_diff(target: str, request_file: str, session_a_file: str, session_b_file: str) -> dict:
    init_evidence_tree(target)
    req_data = json.loads(Path(request_file).read_text())
    req = req_data.get('request', req_data) if isinstance(req_data, dict) else {}
    method = str(req.get('method', 'GET')).upper()
    url = str(req.get('url', ''))
    body = req.get('body', '')

    profile_a = load_session_profile('user_a', session_a_file)
    profile_b = load_session_profile('user_b', session_b_file)

    if method not in SAFE_METHODS:
        require_approval(f'Replay non-safe method {method} to {url}?', 'approval')
    else:
        require_approval(f'Replay safe method {method} to {url}?', 'approval')

    kwargs = {'timeout': 20}
    if method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        kwargs['data'] = body

    r1 = requests.request(method, url, headers=profile_a.headers, cookies=profile_a.cookies, **kwargs)
    r2 = requests.request(method, url, headers=profile_b.headers, cookies=profile_b.cookies, **kwargs)

    t1, t2 = r1.text or '', r2.text or ''
    keys1, keys2 = _json_keys(t1), _json_keys(t2)

    result = {
        'target': target,
        'request': {'method': method, 'url': url},
        'profiles': ['user_a', 'user_b', 'admin', 'guest'],
        'comparison': {
            'status_a': r1.status_code,
            'status_b': r2.status_code,
            'length_a': len(t1),
            'length_b': len(t2),
            'json_keys_only_a': sorted(keys1 - keys2),
            'json_keys_only_b': sorted(keys2 - keys1),
            'content_similarity': _similarity(t1, t2),
            'sensitive_fields_a': _extract_sensitive(t1),
            'sensitive_fields_b': _extract_sensitive(t2),
        },
    }

    out = evidence_path(target, 'ai-analysis', 'replay_diff.json')
    out.write_text(json.dumps(result, indent=2))
    return {'target': target, 'output': str(out), 'status_a': r1.status_code, 'status_b': r2.status_code}
