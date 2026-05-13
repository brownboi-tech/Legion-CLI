def require_approval(command: str, risk: str):
    print('\n[Approval Required]')
    print(f'Risk Level: {risk}')
    print(command)

    answer = input('Approve command? (yes/no): ').strip().lower()

    if answer not in ['y', 'yes']:
        raise Exception('Command rejected by user.')
