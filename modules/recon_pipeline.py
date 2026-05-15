import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.runner import run_command, write_output, tool_exists
from modules.evidence_manager import init_evidence_tree, evidence_path
from storage.database import init_db, insert_endpoint, insert_recon_artifact

API_REGEX = re.compile(r'/(?:api|v\d+)[A-Za-z0-9_\-/{}]*')


def _log(msg: str):
    print(f'[recon-pipeline] {msg}')


def _run_with_retries(command: str, risk: str = 'safe', retries: int = 2, sleep_sec: int = 2) -> str:
    last_err = ''
    for attempt in range(1, retries + 2):
        result = run_command(command, risk=risk)
        if result['returncode'] == 0:
            return result['stdout'] or ''
        last_err = result['stderr'] or f'rc={result["returncode"]}'
        _log(f'Attempt {attempt} failed for `{command}`: {last_err}')
        time.sleep(sleep_sec)
    _log(f'All retries failed for `{command}`')
    return ''


def _save_set(path: Path, values: set[str]):
    write_output(str(path), '\n'.join(sorted(values)))


def run_recon_pipeline(target: str) -> dict:
    start = time.time()
    init_db()
    root = init_evidence_tree(target) / 'recon'
    root.mkdir(parents=True, exist_ok=True)

    subdomains: set[str] = set()
    live_hosts: set[str] = set()
    urls: set[str] = set()

    _log('Starting subdomain discovery')
    futures = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        if tool_exists('subfinder'):
            futures[ex.submit(_run_with_retries, f'subfinder -d {target} -silent')] = 'subfinder'
        if tool_exists('assetfinder'):
            futures[ex.submit(_run_with_retries, f'assetfinder --subs-only {target}')] = 'assetfinder'
        if tool_exists('amass'):
            futures[ex.submit(_run_with_retries, f'amass enum -passive -d {target} -silent', 'approval')] = 'amass'

        for fut in as_completed(futures):
            tool = futures[fut]
            out = fut.result()
            vals = {x.strip() for x in out.splitlines() if x.strip()}
            subdomains.update(vals)
            insert_recon_artifact(target, 'subdomains', tool, str(root / f'{tool}.txt'), len(vals))
            _log(f'{tool}: {len(vals)} subdomains')

    _save_set(root / 'subdomains.txt', subdomains)
    for sd in subdomains:
        insert_endpoint(target, sd, 'subdomain')

    _log('Probing live hosts with httpx')
    if tool_exists('httpx'):
        seed = root / 'subdomains.txt'
        out = _run_with_retries(f'httpx -l {seed} -silent') if seed.exists() else _run_with_retries(f'httpx -u https://{target} -silent')
        live_hosts = {x.strip() for x in out.splitlines() if x.strip()}
    _save_set(root / 'live_hosts.txt', live_hosts)
    insert_recon_artifact(target, 'live-hosts', 'httpx', str(root / 'live_hosts.txt'), len(live_hosts))
    for h in live_hosts:
        insert_endpoint(target, h, 'live-host')

    _log('Collecting URLs from katana/gau/waybackurls')
    with ThreadPoolExecutor(max_workers=3) as ex:
        url_futures = {}
        if tool_exists('katana'):
            url_futures[ex.submit(_run_with_retries, f'katana -list {root / "live_hosts.txt"} -silent' if live_hosts else f'katana -u https://{target} -silent')] = 'katana'
        if tool_exists('gau'):
            url_futures[ex.submit(_run_with_retries, f'gau {target}')] = 'gau'
        if tool_exists('waybackurls'):
            url_futures[ex.submit(_run_with_retries, f'waybackurls {target}')] = 'waybackurls'

        for fut in as_completed(url_futures):
            tool = url_futures[fut]
            out = fut.result()
            vals = {x.strip() for x in out.splitlines() if x.strip()}
            urls.update(vals)
            insert_recon_artifact(target, 'urls', tool, str(root / f'{tool}.txt'), len(vals))
            _log(f'{tool}: {len(vals)} urls')

    _save_set(root / 'urls.txt', urls)
    for u in urls:
        insert_endpoint(target, u, 'url')

    js_files = {u for u in urls if u.lower().endswith('.js') or '.js?' in u.lower()}
    api_endpoints = {m.group(0) for u in urls for m in API_REGEX.finditer(u)}

    _save_set(root / 'js_files.txt', js_files)
    _save_set(root / 'api_endpoints.txt', api_endpoints)
    for js in js_files:
        insert_endpoint(target, js, 'js-file')
    for api in api_endpoints:
        insert_endpoint(target, api, 'api-endpoint')

    elapsed = round(time.time() - start, 2)
    _log(f'Completed in {elapsed}s')
    return {
        'target': target,
        'subdomains': len(subdomains),
        'live_hosts': len(live_hosts),
        'urls': len(urls),
        'js_files': len(js_files),
        'api_endpoints': len(api_endpoints),
        'output_dir': str(root),
        'duration_sec': elapsed,
    }
