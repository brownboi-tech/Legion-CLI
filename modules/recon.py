from pathlib import Path

from core.runner import run_command, tool_exists, write_output
from storage.database import save_endpoint, save_recon_run


def _tool_output_path(base_dir: Path, tool: str) -> Path:
    return base_dir / f"{tool}.txt"


def _run_and_store(tool: str, command: str, target: str, base_dir: Path):
    if not tool_exists(tool):
        print(f'[-] Skipping {tool}: not installed')
        return []

    result = run_command(command)
    stdout = result.get('stdout', '') or ''
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]

    output_path = _tool_output_path(base_dir, tool)
    write_output(str(output_path), '\n'.join(lines) + ('\n' if lines else ''))
    save_recon_run(
        target=target,
        tool=tool,
        command=command,
        output_path=str(output_path),
        returncode=result.get('returncode', 1),
        stdout=stdout,
        stderr=result.get('stderr', '') or '',
    )

    return lines


def run_recon(target: str):
    recon_root = Path('data/recon') / target
    recon_root.mkdir(parents=True, exist_ok=True)

    subdomains = _run_and_store('subfinder', f'subfinder -d {target} -silent', target, recon_root)

    live_hosts = []
    httpx_input = recon_root / 'subfinder.txt'
    if subdomains and tool_exists('httpx'):
        result = run_command(f'httpx -l {httpx_input} -silent')
        stdout = result.get('stdout', '') or ''
        live_hosts = [line.strip() for line in stdout.splitlines() if line.strip()]

        output_path = _tool_output_path(recon_root, 'httpx')
        write_output(str(output_path), '\n'.join(live_hosts) + ('\n' if live_hosts else ''))
        save_recon_run(
            target=target,
            tool='httpx',
            command=f'httpx -l {httpx_input} -silent',
            output_path=str(output_path),
            returncode=result.get('returncode', 1),
            stdout=stdout,
            stderr=result.get('stderr', '') or '',
        )
    elif not tool_exists('httpx'):
        print('[-] Skipping httpx: not installed')

    # URL collection pipeline from multiple sources
    all_urls = set()
    url_sources = {
        'katana': f'katana -u https://{target} -silent',
        'gau': f'gau --subs {target}',
        'waybackurls': f'waybackurls {target}',
    }

    for tool, command in url_sources.items():
        urls = _run_and_store(tool, command, target, recon_root)
        for url in urls:
            all_urls.add(url)
            save_endpoint(target=target, endpoint=url, source=tool)

    # Persist live hosts as endpoints too
    for host in live_hosts:
        save_endpoint(target=target, endpoint=host, source='httpx')

    combined_urls_path = recon_root / 'urls_all.txt'
    combined_urls = sorted(all_urls)
    write_output(
        str(combined_urls_path),
        '\n'.join(combined_urls) + ('\n' if combined_urls else ''),
    )

    print(f'[+] Recon pipeline complete for {target}. Output: {recon_root}')
