import re
from pathlib import Path

from core.runner import run_command, write_output, tool_exists
from storage.database import init_db, insert_recon_artifact, insert_endpoint

RECON_ROOT = Path('data/recon')
ROUTE_REGEX = re.compile(r'/(api|v1|v2)[A-Za-z0-9_\-/]+')


def _run_and_save(command: str, output_path: Path) -> str:
    result = run_command(command)
    content = result['stdout'] or ''
    write_output(str(output_path), content)
    return content


def _save_unique_endpoints(target: str, source: str, lines: str, seen: set[str]):
    for line in lines.splitlines():
        endpoint = line.strip()
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            insert_endpoint(target=target, endpoint=endpoint, source=source)


def run_recon(target: str):
    init_db()
    seen_endpoints: set[str] = set()

    target_dir = RECON_ROOT / target
    subdomains_dir = target_dir / 'subdomains'
    probing_dir = target_dir / 'httpx'
    urls_dir = target_dir / 'urls'
    js_dir = target_dir / 'js'

    for d in (subdomains_dir, probing_dir, urls_dir, js_dir):
        d.mkdir(parents=True, exist_ok=True)

    subfinder_output = ''
    live_output = ''

    if tool_exists('subfinder'):
        subfinder_file = subdomains_dir / 'subfinder.txt'
        subfinder_output = _run_and_save(f'subfinder -d {target} -silent', subfinder_file)
        insert_recon_artifact(target, 'subdomains', 'subfinder', str(subfinder_file), len(subfinder_output.splitlines()))
        _save_unique_endpoints(target, 'subfinder', subfinder_output, seen_endpoints)

    if tool_exists('httpx'):
        seed_file = subdomains_dir / 'subfinder.txt'
        live_file = probing_dir / 'live_hosts.txt'
        live_output = _run_and_save(f'httpx -l {seed_file} -silent', live_file) if seed_file.exists() else _run_and_save(f'httpx -u https://{target} -silent', live_file)
        insert_recon_artifact(target, 'http', 'httpx', str(live_file), len(live_output.splitlines()))
        _save_unique_endpoints(target, 'httpx', live_output, seen_endpoints)

    for tool in ('katana', 'gau', 'waybackurls'):
        if not tool_exists(tool):
            continue
        outfile = urls_dir / f'{tool}.txt'
        command = f'{tool} {target}' if tool != 'katana' else (f'katana -list {probing_dir / "live_hosts.txt"} -silent' if (probing_dir / 'live_hosts.txt').exists() else f'katana -u https://{target} -silent')
        output = _run_and_save(command, outfile)
        insert_recon_artifact(target, 'urls', tool, str(outfile), len(output.splitlines()))
        _save_unique_endpoints(target, tool, output, seen_endpoints)

    js_urls = sorted({u for u in seen_endpoints if '.js' in u.lower()})
    write_output(str(js_dir / 'js_urls.txt'), '\n'.join(js_urls))

    api_patterns = sorted({m for u in seen_endpoints for m in ROUTE_REGEX.findall(u)})
    write_output(str(js_dir / 'js_api_patterns.txt'), '\n'.join(api_patterns))

    write_output(str(target_dir / 'dedup_endpoints.txt'), '\n'.join(sorted(seen_endpoints)))
    print(f'[+] Recon phase complete for {target}')
