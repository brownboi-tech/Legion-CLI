import json
import os
from typing import Any

from openai import OpenAI

from core.approval import require_approval


def plan_next_step(target):
    return f'''[Legion AI Planner]\n\nTarget: {target}\n\nSuggested next actions:\n- Run recon safely\n- Collect JS bundles\n- Classify API endpoints\n- Compare authenticated vs unauthenticated responses\n- Look for IDOR/BOLA patterns\n- Review business logic and payment flows manually\n'''


def _maybe_client() -> OpenAI | None:
    if not os.getenv('OPENAI_API_KEY'):
        return None
    return OpenAI()


def _safe_json_parse(raw: str, default: Any):
    try:
        return json.loads(raw)
    except Exception:
        return default


def classify_endpoints_with_ai(endpoints: list[str]) -> list[dict]:
    if not endpoints:
        return []

    require_approval('Send discovered endpoints to OpenAI for AI classification', 'approval')

    client = _maybe_client()
    if client is None:
        return [
            {'endpoint': ep, 'category': 'general-api', 'confidence': 'low', 'reason': 'OPENAI_API_KEY not configured'}
            for ep in endpoints
        ]

    prompt = (
        'Classify each endpoint for bug bounty attack-surface triage. '
        'Return JSON array of {endpoint, category, confidence, reason}. '
        'Categories: authentication, authorization, payment, admin, graphql, pii, upload, general-api.\n\n'
        + '\n'.join(endpoints)
    )

    response = client.responses.create(
        model='gpt-4.1-mini',
        input=prompt,
    )
    text = response.output_text.strip()
    data = _safe_json_parse(text, [])
    if isinstance(data, list):
        return data
    return []


def auth_diff_with_ai(endpoint: str, unauth_response: str, auth_response: str) -> dict:
    require_approval(f'Send auth diff sample for {endpoint} to OpenAI', 'approval')

    client = _maybe_client()
    if client is None:
        return {
            'endpoint': endpoint,
            'risk': 'unknown',
            'summary': 'OPENAI_API_KEY not configured; manual auth diff required.',
            'signals': [],
        }

    prompt = f'''Compare unauthenticated vs authenticated responses for authz weaknesses.
Return JSON object with keys: endpoint, risk, summary, signals.

Endpoint: {endpoint}

UNAUTH RESPONSE:
{unauth_response[:5000]}

AUTH RESPONSE:
{auth_response[:5000]}
'''

    response = client.responses.create(model='gpt-4.1-mini', input=prompt)
    return _safe_json_parse(response.output_text.strip(), {
        'endpoint': endpoint,
        'risk': 'unknown',
        'summary': 'Could not parse AI output.',
        'signals': [],
    })


def draft_report_with_ai(finding: str, target: str, evidence: str) -> str:
    require_approval(f'Send finding evidence to OpenAI to draft report for {finding}', 'approval')

    client = _maybe_client()
    if client is None:
        return f'''# {finding}

## Target
{target}

## Summary
Manual drafting required because OPENAI_API_KEY is not configured.

## Evidence
{evidence}
'''

    prompt = f'''Draft a concise bug bounty report in Markdown.
Include sections: Title, Summary, Steps to Reproduce, Impact, Evidence, Remediation.
Target: {target}
Finding: {finding}
Evidence:
{evidence[:10000]}
'''
    response = client.responses.create(model='gpt-4.1-mini', input=prompt)
    return response.output_text.strip()
