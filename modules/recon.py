from pathlib import Path

from core.runner import run_command, write_output, tool_exists
from storage.database import init_db, insert_recon_artifact, insert_endpoint


RECON_ROOT = Path('data/recon')


def _run_and_save(command: str, output_path: Path) -> str:
    result = run_command(command)
    content = result['stdout'] or ''
    write_output(str(output_path), content)
    return content


def _save_lines_as_endpoints(target: str, source: str, lines: str):
    for line in lines.splitlines():
        endpoint = line.strip()
        if endpoint:
            insert_endpoint(target=target, endpoint=endpoint, source=source)


def run_recon(target: str):
    init_db()

    target_dir = RECON_ROOT / target
    subdomains_dir = target_dir / 'subdomains'
    probing_dir = target_dir / 'httpx'
    urls_dir = target_dir / 'urls'

    subdomains_dir.mkdir(parents=True, exist_ok=True)
    probing_dir.mkdir(parents=True, exist_ok=True)
    urls_dir.mkdir(parents=True, exist_ok=True)

    subfinder_output = ''
    live_output = ''

    if tool_exists('subfinder'):
        subfinder_file = subdomains_dir / 'subfinder.txt'
        subfinder_output = _run_and_save(f'subfinder -d {target} -silent', subfinder_file)
        insert_recon_artifact(target, 'subdomains', 'subfinder', str(subfinder_file), len(subfinder_output.splitlines()))
        _save_lines_as_endpoints(target, 'subfinder', subfinder_output)

    if tool_exists('httpx'):
        if subfinder_output.strip():
            seed_file = subdomains_dir / 'subfinder.txt'
            live_output = _run_and_save(f'httpx -l {seed_file} -silent', probing_dir / 'live_hosts.txt')
        else:
            live_output = _run_and_save(f'httpx -u https://{target} -silent', probing_dir / 'live_hosts.txt')

        insert_recon_artifact(target, 'http', 'httpx', str(probing_dir / 'live_hosts.txt'), len(live_output.splitlines()))
        _save_lines_as_endpoints(target, 'httpx', live_output)

    if tool_exists('katana'):
        katana_output = ''
        if live_output.strip():
            katana_output = _run_and_save(
                f'katana -list {probing_dir / "live_hosts.txt"} -silent',
                urls_dir / 'katana.txt',
            )
        else:
            katana_output = _run_and_save(f'katana -u https://{target} -silent', urls_dir / 'katana.txt')

        insert_recon_artifact(target, 'urls', 'katana', str(urls_dir / 'katana.txt'), len(katana_output.splitlines()))
        _save_lines_as_endpoints(target, 'katana', katana_output)

    if tool_exists('gau'):
        gau_output = _run_and_save(f'gau {target}', urls_dir / 'gau.txt')
        insert_recon_artifact(target, 'urls', 'gau', str(urls_dir / 'gau.txt'), len(gau_output.splitlines()))
        _save_lines_as_endpoints(target, 'gau', gau_output)

    if tool_exists('waybackurls'):
        wb_output = _run_and_save(f'waybackurls {target}', urls_dir / 'waybackurls.txt')
        insert_recon_artifact(target, 'urls', 'waybackurls', str(urls_dir / 'waybackurls.txt'), len(wb_output.splitlines()))
        _save_lines_as_endpoints(target, 'waybackurls', wb_output)

    print(f'[+] Recon phase complete for {target}')
