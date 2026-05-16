import json
from datetime import datetime

from modules.evidence_manager import evidence_path, init_evidence_tree


def _write_plan(target: str, name: str, steps: list[str], risk: str = 'manual') -> dict:
    init_evidence_tree(target)
    out = evidence_path(target, 'ai-analysis', f'{name}_workflow.json')
    data = {
        'target': target,
        'workflow': name,
        'risk_level': risk,
        'generated_at': datetime.utcnow().isoformat(),
        'steps': steps,
    }
    out.write_text(json.dumps(data, indent=2))
    return {'target': target, 'workflow': name, 'output': str(out), 'steps': len(steps)}


def race_condition_workflow(target: str) -> dict:
    return _write_plan(target, 'race_condition', [
        'Identify state-changing endpoints (cart, coupon, transfer, withdrawal).',
        'Capture baseline request/response with valid auth session.',
        'Replay 10-100 concurrent identical requests with controlled timing gaps.',
        'Compare balances/order states before and after run.',
        'Verify idempotency keys and transaction locks are enforced.',
    ], risk='manual')


def payment_logic_workflow(target: str) -> dict:
    return _write_plan(target, 'payment_logic', [
        'Map order total, discount, shipping, tax, and currency flows.',
        'Test negative, zero, and precision edge values in checkout APIs.',
        'Attempt client-side price tampering and stale-cart checkout.',
        'Test coupon stacking, referral reuse, and gift-card race windows.',
        'Validate payment status cannot be forged by callback parameter edits.',
    ], risk='manual')


def ssrf_chain_workflow(target: str) -> dict:
    return _write_plan(target, 'ssrf_chain', [
        'Enumerate URL fetch features (webhooks, importers, previewers).',
        'Probe schemes/protocols and DNS rebinding behavior safely.',
        'Check cloud metadata endpoints and internal host access controls.',
        'Test redirect chaining and parser differentials across libraries.',
        'Validate egress restrictions, allowlists, and response sanitization.',
    ], risk='approval')


def request_smuggling_workflow(target: str) -> dict:
    return _write_plan(target, 'request_smuggling', [
        'Fingerprint front-end and back-end HTTP parsers/proxies.',
        'Run CL.TE / TE.CL / TE.TE test matrix with benign payload markers.',
        'Check cache poisoning and desync side effects using isolated paths.',
        'Confirm no cross-user response contamination occurs.',
        'Document parser discrepancy and impacted route chain.',
    ], risk='manual')


def mobile_reversing_workflow(target: str) -> dict:
    return _write_plan(target, 'mobile_reversing', [
        'Decompile APK/IPA and inventory API hosts, keys, feature flags.',
        'Check certificate pinning, root/jailbreak checks, and bypass points.',
        'Inspect local storage for tokens/PII/plaintext secrets.',
        'Trace auth/token refresh logic and replay edge cases.',
        'Map deep-link handlers and exported component attack surface.',
    ], risk='manual')


def cloud_misconfig_workflow(target: str) -> dict:
    return _write_plan(target, 'cloud_misconfig', [
        'Enumerate public buckets/blobs and ACL settings.',
        'Check IAM least-privilege and role assumption boundaries.',
        'Validate metadata service protections in compute workloads.',
        'Audit security groups/firewall exposure for admin services.',
        'Review CI/CD and secret management leakage paths.',
    ], risk='approval')


def business_logic_workflow(target: str) -> dict:
    return _write_plan(target, 'business_logic', [
        'Model critical user journeys and state transitions.',
        'Test privilege transitions across roles/tenants/org boundaries.',
        'Abuse sequence/order dependencies and rollback conditions.',
        'Validate policy invariants under parallel actions and retries.',
        'Document monetization or trust-impacting bypass scenarios.',
    ], risk='manual')
