import json
from urllib.parse import parse_qs, urlparse

from modules.evidence_manager import evidence_path, init_evidence_tree


def oauth_check(target: str, auth_url: str) -> dict:
    init_evidence_tree(target)
    parsed = urlparse(auth_url)
    params = parse_qs(parsed.query)

    redirect_uri = (params.get('redirect_uri') or [''])[0]
    state = (params.get('state') or [''])[0]
    response_type = (params.get('response_type') or [''])[0]

    findings = {
        'target': target,
        'auth_url': auth_url,
        'redirect_uri': redirect_uri,
        'checks': {
            'redirect_uri_missing': not bool(redirect_uri),
            'redirect_uri_non_https': bool(redirect_uri) and not redirect_uri.startswith('https://'),
            'state_missing': not bool(state),
            'state_weak_short': bool(state) and len(state) < 16,
            'implicit_or_hybrid_flow_hint': response_type in {'token', 'id_token', 'token id_token'},
        },
        'token_leakage_indicators': [
            'response_type=token may expose tokens in URL fragments' if response_type == 'token' else '',
            'redirect_uri contains localhost or custom scheme; verify safe client handling' if ('localhost' in redirect_uri or '://' in redirect_uri and not redirect_uri.startswith('https://')) else '',
        ],
        'open_redirect_hints': [
            'redirect_uri appears user-controlled via query/path parameters' if ('?' in redirect_uri and ('next=' in redirect_uri or 'url=' in redirect_uri or 'redirect=' in redirect_uri)) else '',
            'wildcard-like redirect pattern detected' if '*' in redirect_uri else '',
        ],
        'account_linking_risk_notes': [
            'Verify linking flow binds OAuth identity to authenticated session with CSRF/state checks.',
            'Verify email-only trust does not allow takeover when provider email is unverified.',
        ],
        'weak_state_usage_checklist': [
            'State should be high entropy (>=128 bits).',
            'State should be single-use and bound to user session.',
            'State should be validated on callback exactly.',
        ],
    }

    findings['token_leakage_indicators'] = [x for x in findings['token_leakage_indicators'] if x]
    findings['open_redirect_hints'] = [x for x in findings['open_redirect_hints'] if x]

    out = evidence_path(target, 'ai-analysis', 'oauth_analysis.json')
    out.write_text(json.dumps(findings, indent=2))
    return {'target': target, 'output': str(out), 'issues': sum(1 for v in findings['checks'].values() if v)}
