import json

from ai.reasoner import classify_endpoints_with_ai, auth_diff_with_ai
from storage.database import insert_auth_diff, insert_endpoint_classification


def classify_and_store_endpoints(target: str, endpoints: list[str]) -> list[dict]:
    rows = classify_endpoints_with_ai(endpoints)
    for row in rows:
        insert_endpoint_classification(
            target=target,
            endpoint=row.get('endpoint', ''),
            category=row.get('category', 'general-api'),
            confidence=row.get('confidence', 'unknown'),
            reason=row.get('reason', ''),
        )
    return rows


def run_auth_diff(target: str, endpoint: str, unauth_response: str, auth_response: str) -> dict:
    diff = auth_diff_with_ai(endpoint, unauth_response, auth_response)
    insert_auth_diff(
        target=target,
        endpoint=endpoint,
        risk=diff.get('risk', 'unknown'),
        summary=diff.get('summary', ''),
        signals=json.dumps(diff.get('signals', [])),
    )
    return diff
