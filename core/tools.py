TOOLS = {
    'safe': [
        'subfinder', 'httpx', 'katana', 'gau', 'waybackurls', 'subjs', 'playwright', 'burp-import', 'caido-import'
    ],
    'approval': [
        'ffuf', 'arjun', 'dalfox', 'nmap', 'nuclei'
    ],
    'manual': [
        'sqlmap', 'commix', 'race-testing', 'request-smuggling'
    ]
}


def list_tools():
    print('\n[Legion Tool Registry]\n')
    for level, tools in TOOLS.items():
        print(f'{level.upper()}:')
        for tool in tools:
            print(f'  - {tool}')
        print()
