import json
import re
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from core.approval import require_approval
from modules.evidence_manager import evidence_path, init_evidence_tree

ID_PATTERN = re.compile(r'(?<![A-Za-z0-9])(?:\d{2,}|[0-9a-fA-F]{8,})(?![A-Za-z0-9])')


@dataclass
class IDORPlanItem:
    method: str
    original_url: str
    mutated_url: str
    object_id: str
    source: str
    risk_note: str


def _read_json(path: Path):
    return json.loads(path.read_text())


def _extract_json_ids(body: str) -> list[str]:
    try:
        data = json.loads(body)
        return ID_PATTERN.findall(json.dumps(data))
    except Exception:
        return ID_PATTERN.findall(body or '')


def _mutate_id(value: str) -> str:
    return str(int(value) + 1) if value.isdigit() else value[::-1]


def _mutate_url(url: str, object_id: str) -> str:
    parts = urlsplit(url)
    path = parts.path.replace(object_id, _mutate_id(object_id), 1) if object_id in parts.path else parts.path
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for k, v in query.items():
        if object_id in v:
            query[k] = v.replace(object_id, _mutate_id(object_id), 1)
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query), parts.fragment))


def generate_idor_plan(target: str, replay_file: str) -> dict:
    init_evidence_tree(target)
    replay_path = Path('evidence') / target / 'replay' / replay_file
    sessions = _read_json(replay_path)
    if isinstance(sessions, dict):
        sessions = [sessions]

    plan: list[IDORPlanItem] = []
    for entry in sessions:
        req = entry.get('request', {}) if isinstance(entry, dict) else {}
        method = str(req.get('method', 'GET')).upper()
        url = str(req.get('url', ''))
        body = str(req.get('body', ''))

        ids = sorted(set(ID_PATTERN.findall(url) + _extract_json_ids(body)))
        for object_id in ids:
            plan.append(
                IDORPlanItem(
                    method=method,
                    original_url=url,
                    mutated_url=_mutate_url(url, object_id),
                    object_id=object_id,
                    source='replay',
                    risk_note='Plan only. Replay requires explicit human approval.',
                )
            )

    plan_file = evidence_path(target, 'ai-analysis', 'idor_plan.json')
    plan_file.write_text(json.dumps([asdict(p) for p in plan], indent=2))
    return {'target': target, 'plan_file': str(plan_file), 'items': len(plan)}


def _similarity(a: str, b: str) -> float:
    return round(SequenceMatcher(None, a or '', b or '').ratio(), 4)


def run_idor_test(target: str, plan_file: str, user_a_token: str, user_b_token: str, timeout: int = 20) -> dict:
    plans = _read_json(Path(plan_file))
    results = []

    for plan in plans:
        method = str(plan.get('method', 'GET')).upper()
        if method != 'GET':
            continue

        mutated_url = plan.get('mutated_url', '')
        require_approval(f'Run IDOR GET replay against {mutated_url}?', 'approval')

        headers_a = {'Authorization': f'Bearer {user_a_token}'} if user_a_token else {}
        headers_b = {'Authorization': f'Bearer {user_b_token}'} if user_b_token else {}

        resp_a = requests.get(mutated_url, headers=headers_a, timeout=timeout)
        resp_b = requests.get(mutated_url, headers=headers_b, timeout=timeout)

        body_a = resp_a.text or ''
        body_b = resp_b.text or ''
        results.append(
            {
                'plan': plan,
                'user_a': {'status': resp_a.status_code, 'length': len(body_a)},
                'user_b': {'status': resp_b.status_code, 'length': len(body_b)},
                'content_similarity': _similarity(body_a, body_b),
            }
        )

    out = evidence_path(target, 'ai-analysis', 'idor_results.json')
    out.write_text(json.dumps(results, indent=2))
    return {'target': target, 'results': len(results), 'output': str(out)}
