import json
import re
from pathlib import Path

from ai.reasoner import auth_diff_with_ai
from modules.evidence_manager import evidence_path, init_evidence_tree

ID_PATTERN = re.compile(r'(?<![A-Za-z0-9])(?:\d{2,}|[0-9a-fA-F]{8,})(?![A-Za-z0-9])')


def analyze_idor_from_replay(target: str, replay_file: str) -> dict:
    init_evidence_tree(target)
    data = json.loads(Path(replay_file).read_text())
    if isinstance(data, dict):
        sessions = [data]
    else:
        sessions = data

    findings = []
    for entry in sessions:
        req = entry.get('request', {})
        resp = entry.get('response', {})
        req_text = json.dumps(req)
        resp_text = json.dumps(resp)
        ids = sorted(set(ID_PATTERN.findall(req_text + '\n' + resp_text)))
        if not ids:
            continue

        mutated = req_text
        if ids:
            mutated = mutated.replace(ids[0], str(int(ids[0], 16) + 1) if ids[0].isalnum() else ids[0]) if ids[0].isdigit() else mutated.replace(ids[0], ids[0][::-1])

        ai = auth_diff_with_ai(req.get('url', 'unknown'), req_text, mutated)
        findings.append({'url': req.get('url'), 'object_ids': ids, 'ai_risk': ai})

    out = evidence_path(target, 'ai-analysis', 'idor_bola_analysis.json')
    out.write_text(json.dumps(findings, indent=2))
    return {'target': target, 'findings': len(findings), 'output': str(out)}
