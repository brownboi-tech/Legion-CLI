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
SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


@dataclass
class ReplayPlan:
    name: str
    original_url: str
    mutated_url: str
    method: str
    object_id: str
    risk_note: str


def _read_sessions(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _extract_ids_from_text(text: str) -> list[str]:
    return sorted(set(ID_PATTERN.findall(text or '')))


def _mutate_first_id(value: str) -> str:
    if value.isdigit():
        return str(int(value) + 1)
    return value[::-1]


def _mutate_url(url: str, object_id: str) -> str:
    if object_id in url:
        return url.replace(object_id, _mutate_first_id(object_id), 1)

    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, val in query.items():
        if object_id in val:
            query[key] = val.replace(object_id, _mutate_first_id(object_id), 1)
            return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return url


def generate_safe_replay_plans(session_file: str) -> list[ReplayPlan]:
    sessions = _read_sessions(session_file)
    plans: list[ReplayPlan] = []

    for idx, item in enumerate(sessions, start=1):
        request = item.get('request', {}) if isinstance(item, dict) else {}
        method = str(request.get('method', 'GET')).upper()
        url = str(request.get('url', ''))
        body = str(request.get('body', ''))
        object_ids = sorted(set(_extract_ids_from_text(url) + _extract_ids_from_text(body)))

        for obj_id in object_ids:
            mutated = _mutate_url(url, obj_id)
            plans.append(
                ReplayPlan(
                    name=f'idor-plan-{idx}-{obj_id}',
                    original_url=url,
                    mutated_url=mutated,
                    method=method,
                    object_id=obj_id,
                    risk_note='Non-destructive replay only; unsafe methods skipped by default.',
                )
            )

    return plans


def _similarity(a: str, b: str) -> float:
    return round(SequenceMatcher(None, a or '', b or '').ratio(), 4)


def run_safe_idor_replay(target: str, session_file: str, timeout: int = 20) -> dict:
    init_evidence_tree(target)
    plans = generate_safe_replay_plans(session_file)

    results = []
    skipped = []

    for plan in plans:
        if plan.method not in SAFE_METHODS:
            skipped.append({'plan': asdict(plan), 'reason': f'Unsafe method {plan.method} auto-skipped'})
            continue

        require_approval(
            f'Replay safe IDOR test? {plan.method} {plan.mutated_url}',
            'approval',
        )

        try:
            original_resp = requests.request(plan.method, plan.original_url, timeout=timeout)
            mutated_resp = requests.request(plan.method, plan.mutated_url, timeout=timeout)
        except Exception as exc:
            results.append({'plan': asdict(plan), 'error': str(exc)})
            continue

        original_body = original_resp.text or ''
        mutated_body = mutated_resp.text or ''

        results.append(
            {
                'plan': asdict(plan),
                'comparison': {
                    'status_original': original_resp.status_code,
                    'status_mutated': mutated_resp.status_code,
                    'body_len_original': len(original_body),
                    'body_len_mutated': len(mutated_body),
                    'content_similarity': _similarity(original_body, mutated_body),
                },
            }
        )

    output_file = evidence_path(target, 'ai-analysis', 'idor_safe_replay_results.json')
    output_file.write_text(json.dumps({'results': results, 'skipped': skipped}, indent=2))

    return {
        'target': target,
        'plans': len(plans),
        'executed': len(results),
        'skipped': len(skipped),
        'output': str(output_file),
    }
