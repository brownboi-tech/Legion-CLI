import re
from pathlib import Path

from core.runner import write_output
from modules.evidence_manager import evidence_path, init_evidence_tree

ROUTE_REGEX = re.compile(r'/(?:api|v\d+)[A-Za-z0-9_\-/{}]*')


def extract_js_routes(target: str, js_file: str) -> dict:
    init_evidence_tree(target)
    data = Path(js_file).read_text(errors='ignore')
    routes = sorted(set(ROUTE_REGEX.findall(data)))
    out = evidence_path(target, 'ai-analysis', 'js_routes.txt')
    write_output(str(out), '\n'.join(routes))
    return {'target': target, 'routes': len(routes), 'output': str(out)}
