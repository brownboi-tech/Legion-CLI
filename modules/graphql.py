def graphql_check(endpoint: str):
    print('[+] GraphQL inspection checklist')
    print(f'- Endpoint: {endpoint}')
    print('- Check introspection')
    print('- Check batching abuse')
    print('- Check authorization')
    print('- Check nested query limits')
