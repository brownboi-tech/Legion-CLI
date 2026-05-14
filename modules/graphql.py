import json

import requests

from modules.evidence_manager import evidence_path, init_evidence_tree

INTROSPECTION_QUERY = '{ __schema { queryType { name } mutationType { name } types { name } } }'


def graphql_check(endpoint: str, target: str) -> dict:
    init_evidence_tree(target)
    summary = {'endpoint': endpoint, 'introspection': 'unknown', 'status': None}

    try:
        resp = requests.post(endpoint, json={'query': INTROSPECTION_QUERY}, timeout=20)
        summary['status'] = resp.status_code
        data = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
        summary['introspection'] = 'enabled' if isinstance(data, dict) and data.get('data', {}).get('__schema') else 'disabled_or_filtered'
        summary['response_sample'] = (resp.text or '')[:500]
    except Exception as exc:
        summary['error'] = str(exc)

    out = evidence_path(target, 'ai-analysis', 'graphql_analysis.json')
    out.write_text(json.dumps(summary, indent=2))
    return {'target': target, 'output': str(out), 'status': summary.get('status')}
