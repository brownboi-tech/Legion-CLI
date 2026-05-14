import json

from ai.reasoner import classify_endpoints_with_ai, auth_diff_with_ai
from modules.evidence_manager import evidence_path, normalize_target
from storage.database import init_db, insert_auth_diff, insert_endpoint_classification


def classify_and_store_endpoints(target: str, endpoints: list[str]) -> list[dict]:
    init_db()
    rows = classify_endpoints_with_ai(endpoints)
    for row in rows:
        insert_endpoint_classification(
            target=target,
            endpoint=row.get('endpoint', ''),
            category=row.get('category', 'general-api'),
            confidence=row.get('confidence', 'unknown'),
            reason=row.get('reason', ''),
        )

    out = evidence_path(target, 'ai-analysis', 'endpoint_classification.json')
    out.write_text(json.dumps(rows, indent=2))
    return rows


def run_auth_diff(target: str, endpoint: str, unauth_response: str, auth_response: str) -> dict:
    init_db()
    diff = auth_diff_with_ai(endpoint, unauth_response, auth_response)
    insert_auth_diff(
        target=target,
        endpoint=endpoint,
        risk=diff.get('risk', 'unknown'),
        summary=diff.get('summary', ''),
        signals=json.dumps(diff.get('signals', [])),
    )

    safe_name = normalize_target(endpoint).replace('/', '_')
    out = evidence_path(target, 'ai-analysis', f'auth_diff_{safe_name}.json')
    out.write_text(json.dumps(diff, indent=2))
    return diff
