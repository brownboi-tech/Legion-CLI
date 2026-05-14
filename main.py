import argparse
from core.tools import list_tools
from core.scope import validate_scope
from core.report import create_report
from ai.reasoner import plan_next_step
from modules.recon import run_recon
from storage.database import init_db


def main():
    parser = argparse.ArgumentParser(description='Legion CLI')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('tools')

    recon = sub.add_parser('recon')
    recon.add_argument('target')
    recon.add_argument('--scope', default='scope.yaml')

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

    args = parser.parse_args()

    init_db()

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
        create_report(args.finding, args.target)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
