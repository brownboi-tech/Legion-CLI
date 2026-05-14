import base64
import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from modules.evidence_manager import evidence_path, init_evidence_tree
from storage.database import init_db, insert_endpoint, insert_recon_artifact
from traffic.models import Request, Response, Session, Token, headers_from_dict


URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
ID_PATTERN = re.compile(r'(?<![A-Za-z0-9])(?:\d{2,}|[0-9a-fA-F]{8,})(?![A-Za-z0-9])')


def _extract_urls(text: str) -> set[str]:
    return set(URL_PATTERN.findall(text or ''))


def _extract_tokens(headers: dict[str, str], body: str) -> list[Token]:
    tokens: list[Token] = []
    auth = headers.get('Authorization') or headers.get('authorization')
    if auth:
        tokens.append(Token(token_type='authorization', value=auth, source='header'))
    for match in re.findall(r'(?i)(?:token|jwt|bearer)["\s:=]+([A-Za-z0-9._-]{8,})', body or ''):
        tokens.append(Token(token_type='candidate', value=match, source='body'))
    return tokens


def import_burp_xml(file_path: str, target: str | None = None) -> dict:
    p = Path(file_path)
    root = ET.fromstring(p.read_text(errors='ignore'))

    urls: set[str] = set()
    normalized: list[dict] = []

    for item in root.findall('.//item'):
        url = ((item.findtext('url') or '').strip())
        if url:
            urls.add(url)

        request_blob = ''
        response_blob = ''
        req_node = item.find('request')
        resp_node = item.find('response')

        if req_node is not None and req_node.text:
            request_blob = req_node.text
            if req_node.attrib.get('base64', '').lower() == 'true':
                request_blob = base64.b64decode(request_blob).decode('utf-8', errors='ignore')
            urls.update(_extract_urls(request_blob))

        if resp_node is not None and resp_node.text:
            response_blob = resp_node.text
            if resp_node.attrib.get('base64', '').lower() == 'true':
                response_blob = base64.b64decode(response_blob).decode('utf-8', errors='ignore')
            urls.update(_extract_urls(response_blob))

        req = Request(method='GET', url=url or 'unknown', headers=[], body=request_blob)
        resp = Response(status_code=200, headers=[], body=response_blob)
        sess = Session(session_id=f'burp-{len(normalized)+1}')
        normalized.append({
            'request': req.__dict__,
            'response': resp.__dict__,
            'session': sess.__dict__,
            'tokens': [t.__dict__ for t in _extract_tokens({}, request_blob)],
            'object_ids': ID_PATTERN.findall((request_blob or '') + '\n' + (response_blob or '')),
        })

    resolved_target = target or (next(iter(urls)).split('/')[2] if urls else 'unknown-target')
    _persist_import_results(resolved_target, 'burp', sorted(urls), normalized)
    return {'target': resolved_target, 'count': len(urls), 'source': 'burp'}


def import_caido_json(file_path: str, target: str | None = None) -> dict:
    p = Path(file_path)
    raw = p.read_text(errors='ignore').strip()
    urls: set[str] = set()
    normalized: list[dict] = []

    records = json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()] if not raw.startswith('{') else [json.loads(raw)]

    for rec in records:
        if not isinstance(rec, dict):
            continue
        url = rec.get('url') or rec.get('final_url') or rec.get('endpoint') or 'unknown'
        if isinstance(url, str) and url.startswith('http'):
            urls.add(url)

        req_obj = rec.get('request') if isinstance(rec.get('request'), dict) else {}
        resp_obj = rec.get('response') if isinstance(rec.get('response'), dict) else {}

        req_headers = {k: str(v) for k, v in (req_obj.get('headers', {}) or {}).items()} if isinstance(req_obj.get('headers', {}), dict) else {}
        resp_headers = {k: str(v) for k, v in (resp_obj.get('headers', {}) or {}).items()} if isinstance(resp_obj.get('headers', {}), dict) else {}

        req_body = str(req_obj.get('body', ''))
        resp_body = str(resp_obj.get('body', ''))
        urls.update(_extract_urls(req_body))
        urls.update(_extract_urls(resp_body))

        req = Request(method=str(req_obj.get('method', 'GET')), url=str(url), headers=headers_from_dict(req_headers), body=req_body)
        resp = Response(status_code=int(resp_obj.get('status', 0) or 0), headers=headers_from_dict(resp_headers), body=resp_body)
        sess = Session(session_id=f'caido-{len(normalized)+1}')
        normalized.append({
            'request': req.__dict__,
            'response': resp.__dict__,
            'session': sess.__dict__,
            'tokens': [t.__dict__ for t in _extract_tokens(req_headers, req_body)],
            'object_ids': ID_PATTERN.findall((req_body or '') + '\n' + (resp_body or '')),
        })

    resolved_target = target or (next(iter(urls)).split('/')[2] if urls else 'unknown-target')
    _persist_import_results(resolved_target, 'caido', sorted(urls), normalized)
    return {'target': resolved_target, 'count': len(urls), 'source': 'caido'}


def _persist_import_results(target: str, source: str, urls: list[str], normalized: list[dict]):
    init_evidence_tree(target)
    replay_file = evidence_path(target, 'replay', f'{source}_import_urls.json')
    replay_file.write_text(json.dumps(urls, indent=2))
    normalized_file = evidence_path(target, 'replay', f'{source}_normalized_sessions.json')
    normalized_file.write_text(json.dumps(normalized, indent=2))

    init_db()
    for url in urls:
        insert_endpoint(target=target, endpoint=url, source=source)
    insert_recon_artifact(target, 'traffic-import', source, str(normalized_file), len(urls))
