from pathlib import Path
from urllib.parse import urlparse


EVIDENCE_SUBDIRS = [
    'requests',
    'responses',
    'screenshots',
    'ai-analysis',
    'replay',
]


def normalize_target(target: str) -> str:
    parsed = urlparse(target)
    candidate = parsed.netloc or parsed.path or target
    return candidate.replace(':', '_').strip('/').strip() or 'unknown-target'


def init_evidence_tree(target: str) -> Path:
    normalized = normalize_target(target)
    root = Path('evidence') / normalized
    root.mkdir(parents=True, exist_ok=True)
    for sub in EVIDENCE_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


def evidence_path(target: str, category: str, filename: str) -> Path:
    root = init_evidence_tree(target)
    if category not in EVIDENCE_SUBDIRS:
        raise ValueError(f'Unknown evidence category: {category}')
    return root / category / filename
