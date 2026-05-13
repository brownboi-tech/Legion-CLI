from core.runner import run_command, write_output, tool_exists


def run_recon(target: str):
    if tool_exists('subfinder'):
        result = run_command(f'subfinder -d {target} -silent')
        write_output(f'data/recon/{target}_subdomains.txt', result['stdout'])

    if tool_exists('httpx'):
        result = run_command(f'httpx -u https://{target} -silent')
        write_output(f'data/recon/{target}_live.txt', result['stdout'])

    print('[+] Recon phase complete')
