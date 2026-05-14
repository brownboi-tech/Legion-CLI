import argparse
from pathlib import Path

from core.tools import list_tools
from core.scope import validate_scope
from core.report import create_report
from ai.reasoner import plan_next_step
from modules.recon import run_recon
from modules.api_analyzer import classify_and_store_endpoints, run_auth_diff
from browser.playwright_capture import BrowserCapture
from modules.traffic_import import import_burp_xml, import_caido_json


def _read_text(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ''
    return p.read_text()


def _read_lines(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description='Legion CLI')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('tools')

    recon = sub.add_parser('recon')
    recon.add_argument('target')
    recon.add_argument('--scope', default='scope.yaml')

    classify = sub.add_parser('classify-endpoints')
    classify.add_argument('target')
    classify.add_argument('--input', required=True, help='Path to file with one endpoint per line')
    classify.add_argument('--scope', default='scope.yaml')

    authdiff = sub.add_parser('auth-diff')
    authdiff.add_argument('target')
    authdiff.add_argument('--endpoint', required=True)
    authdiff.add_argument('--unauth-file', required=True)
    authdiff.add_argument('--auth-file', required=True)
    authdiff.add_argument('--scope', default='scope.yaml')

    capture = sub.add_parser('capture-traffic')
    capture.add_argument('url')
    capture.add_argument('--wait-ms', type=int, default=5000)

    imp = sub.add_parser('import-traffic')
    imp.add_argument('source', choices=['burp', 'caido'])
    imp.add_argument('file')
    imp.add_argument('--target')

    js = sub.add_parser('js')
    js.add_argument('target')
    js.add_argument('--scope', default='scope.yaml')

    api = sub.add_parser('api')
    api.add_argument('target')
    api.add_argument('--scope', default='scope.yaml')

    ai_plan = sub.add_parser('ai-plan')
    ai_plan.add_argument('target')

    report = sub.add_parser('report')
    report.add_argument('finding')
    report.add_argument('--target', required=True)
    report.add_argument('--ai-draft', action='store_true')
    report.add_argument('--evidence-file', help='Optional markdown/text file used as report evidence context')

    args = parser.parse_args()

    if args.command == 'tools':
        list_tools()

    elif args.command == 'recon':
        validate_scope(args.target, args.scope)
        run_recon(args.target)

    elif args.command == 'classify-endpoints':
        validate_scope(args.target, args.scope)
        endpoints = _read_lines(args.input)
        rows = classify_and_store_endpoints(args.target, endpoints)
        print(f'[+] Classified {len(rows)} endpoints')

    elif args.command == 'auth-diff':
        validate_scope(args.target, args.scope)
        unauth = _read_text(args.unauth_file)
        auth = _read_text(args.auth_file)
        diff = run_auth_diff(args.target, args.endpoint, unauth, auth)
        print(diff)

    elif args.command == 'capture-traffic':
        result = BrowserCapture().capture(args.url, wait_ms=args.wait_ms)
        print(result)

    elif args.command == 'import-traffic':
        if args.source == 'burp':
            result = import_burp_xml(args.file, target=args.target)
        else:
            result = import_caido_json(args.file, target=args.target)
        print(result)

    elif args.command == 'js':
        validate_scope(args.target, args.scope)
        print(f'[+] JS intelligence workflow prepared for {args.target}')

    elif args.command == 'api':
        validate_scope(args.target, args.scope)
        print(f'[+] API analysis workflow prepared for {args.target}')

    elif args.command == 'ai-plan':
        print(plan_next_step(args.target))

    elif args.command == 'report':
        evidence = _read_text(args.evidence_file) if args.evidence_file else ''
        create_report(args.finding, args.target, ai_draft=args.ai_draft, evidence=evidence)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
