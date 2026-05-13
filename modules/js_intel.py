import re
import requests


ROUTE_REGEX = r'/(api|v1|v2)[A-Za-z0-9_\-/]+'


def analyze_js(url: str):
    print(f'[+] Fetching JS: {url}')

    response = requests.get(url, timeout=30)
    matches = set(re.findall(ROUTE_REGEX, response.text))

    print('[+] Potential API patterns:')
    for match in matches:
        print(f'  - {match}')
