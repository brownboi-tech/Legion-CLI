import json
from pathlib import Path

from modules.evidence_manager import evidence_path, init_evidence_tree


def _severity(score: int) -> str:
    if score >= 9:
        return 'critical'
    if score >= 7:
        return 'high'
    if score >= 4:
        return 'medium'
    return 'low'


def _confidence(score: int, signals: int) -> str:
    if score >= 9 and signals >= 2:
        return 'high'
    if score >= 7:
        return 'medium'
    return 'low'


def rank_findings(target: str) -> dict:
    init_evidence_tree(target)
    base = Path('evidence') / target / 'ai-analysis'
    findings = []

    idor = base / 'idor_bola_analysis.json'
    if idor.exists():
        data = json.loads(idor.read_text())
        for i, row in enumerate(data if isinstance(data, list) else [], start=1):
            score = 8
            signals = 1
            ai = row.get('ai_risk', {}) if isinstance(row, dict) else {}
            txt = (json.dumps(ai) or '').lower()
            if any(k in txt for k in ['critical', 'admin', 'sensitive', 'exposure']):
                score = 9
                signals += 1
            findings.append({
                'id': f'idor-{i}',
                'type': 'idor/bola',
                'score': score,
                'severity': _severity(score),
                'confidence': _confidence(score, signals),
                'cwe': ['CWE-639', 'CWE-284'],
                'evidence': 'idor_bola_analysis.json',
                'summary': 'Potential horizontal/vertical authorization bypass from replay analysis.',
            })

    rep = base / 'replay_diff.json'
    if rep.exists():
        d = json.loads(rep.read_text())
        c = d.get('comparison', {}) if isinstance(d, dict) else {}
        score = 5
        signals = 0
        if c.get('status_a') == 200 and c.get('status_b') == 200:
            score = 7
            signals += 1
        if c.get('content_similarity', 0) > 0.9:
            score = max(score, 8)
            signals += 1
        if c.get('sensitive_fields_b'):
            score = 9
            signals += 2
        findings.append({
            'id': 'replay-diff-1',
            'type': 'authz-diff',
            'score': score,
            'severity': _severity(score),
            'confidence': _confidence(score, signals),
            'cwe': ['CWE-200', 'CWE-284'],
            'evidence': 'replay_diff.json',
            'summary': 'Session-differential replay indicates possible data exposure or authz weakness.',
        })

    oauth = base / 'oauth_analysis.json'
    if oauth.exists():
        d = json.loads(oauth.read_text())
        checks = d.get('checks', {}) if isinstance(d, dict) else {}
        score = min(8, 3 + sum(1 for v in checks.values() if v))
        findings.append({
            'id': 'oauth-1',
            'type': 'oauth-misconfig',
            'score': score,
            'severity': _severity(score),
            'confidence': _confidence(score, 1),
            'cwe': ['CWE-601', 'CWE-352'],
            'evidence': 'oauth_analysis.json',
            'summary': 'OAuth redirect/state weaknesses may enable account compromise or token leakage.',
        })

    findings = sorted(findings, key=lambda x: x['score'], reverse=True)
    top5 = findings[:5]

    ranked = {'target': target, 'findings': findings, 'top5': top5}
    out = evidence_path(target, 'ai-analysis', 'ranked_findings.json')
    out.write_text(json.dumps(ranked, indent=2))

    top_md = evidence_path(target, 'ai-analysis', 'top_critical_candidates.md')
    lines = [f"# Top Critical/High Candidates for {target}", ""]
    for f in top5:
        lines += [f"## {f['id']} ({f['severity'].upper()})", f"- Type: {f['type']}", f"- Confidence: {f['confidence']}", f"- CWE: {', '.join(f['cwe'])}", f"- Evidence: {f['evidence']}", f"- Summary: {f['summary']}", ""]
    top_md.write_text('\n'.join(lines))

    return {
        'target': target,
        'count': len(findings),
        'output': str(out),
        'top_candidates_markdown': str(top_md),
        'top_severity': findings[0]['severity'] if findings else 'none',
    }
