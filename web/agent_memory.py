import json
from pathlib import Path
from uuid import uuid4

ROOT = Path('data/agent_sessions')
ROOT.mkdir(parents=True, exist_ok=True)


def load_session(session_id: str | None):
    sid = session_id or str(uuid4())
    path = ROOT / f'{sid}.json'
    if path.exists():
        return sid, json.loads(path.read_text())
    data = {'session_id': sid, 'messages': [], 'current_target': '', 'current_scope': 'scope.yaml', 'last_results': {}, 'pending_confirmation': None}
    path.write_text(json.dumps(data, indent=2))
    return sid, data


def save_session(session_id: str, data: dict):
    (ROOT / f'{session_id}.json').write_text(json.dumps(data, indent=2))
