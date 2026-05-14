import argparse
from pathlib import Path

from core.tools import list_tools
from core.scope import validate_scope
from core.report import create_report
from ai.reasoner import plan_next_step
from modules.recon import run_recon


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
