import base64
import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from storage.database import init_db, insert_endpoint, insert_recon_artifact


def _extract_urls(text: str) -> set[str]:
    return set(re.findall(r'https?://[^\s"\'<>]+', text))


def import_burp_xml(file_path: str, target: str | None = None) -> dict:
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(file_path)

    root = ET.fromstring(p.read_text(errors='ignore'))

    urls: set[str] = set()
    for item in root.findall('.//item'):
        url_node = item.find('url')
        if url_node is not None and (url_node.text or '').strip():
            urls.add(url_node.text.strip())

        for node_name in ('request', 'response'):
            node = item.find(node_name)
            if node is None or not node.text:
                continue
            payload = node.text
            if node.attrib.get('base64', '').lower() == 'true':
                try:
                    payload = base64.b64decode(payload).decode('utf-8', errors='ignore')
                except Exception:
                    continue
            urls.update(_extract_urls(payload))

    resolved_target = target or (next(iter(urls)).split('/')[2] if urls else 'unknown-target')
    _persist_import_results(resolved_target, 'burp', file_path, sorted(urls))
    return {'target': resolved_target, 'count': len(urls), 'source': 'burp'}


def import_caido_json(file_path: str, target: str | None = None) -> dict:
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(file_path)

    raw = p.read_text(errors='ignore').strip()
    urls: set[str] = set()

    # Support plain JSON array/object and line-delimited JSON.
    if raw.startswith('{') or raw.startswith('['):
        data = json.loads(raw)
        records = data if isinstance(data, list) else [data]
    else:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]

    for rec in records:
        if isinstance(rec, dict):
            for key in ('url', 'final_url', 'endpoint'):
                value = rec.get(key)
                if isinstance(value, str) and value.startswith('http'):
                    urls.add(value)

            nested = rec.get('request') or rec.get('response') or {}
            if isinstance(nested, dict):
                for v in nested.values():
                    if isinstance(v, str):
                        urls.update(_extract_urls(v))

    resolved_target = target or (next(iter(urls)).split('/')[2] if urls else 'unknown-target')
    _persist_import_results(resolved_target, 'caido', file_path, sorted(urls))
    return {'target': resolved_target, 'count': len(urls), 'source': 'caido'}


def _persist_import_results(target: str, source: str, file_path: str, urls: list[str]):
    init_db()
    for url in urls:
        insert_endpoint(target=target, endpoint=url, source=source)
    insert_recon_artifact(
        target=target,
        phase='traffic-import',
        tool=source,
        file_path=file_path,
        line_count=len(urls),
    )
