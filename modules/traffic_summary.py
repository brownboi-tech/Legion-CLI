import json
from pathlib import Path


def traffic_summary(target: str) -> dict:
    replay_dir = Path('evidence') / target / 'replay'
    if not replay_dir.exists():
        return {'target': target, 'error': 'No replay directory found'}

    req_count = resp_count = tokens = object_ids = endpoints = 0
    for f in replay_dir.glob('*normalized_sessions.json'):
        data = json.loads(f.read_text())
        for item in data:
            if item.get('request'): req_count += 1
            if item.get('response'): resp_count += 1
            tokens += len(item.get('tokens', []))
            object_ids += len(set(item.get('object_ids', [])))
            endpoints += 1 if item.get('request', {}).get('url') else 0

    return {
        'target': target,
        'requests': req_count,
        'responses': resp_count,
        'token_candidates': tokens,
        'object_ids': object_ids,
        'endpoints': endpoints,
    }
