def classify_endpoint(endpoint: str):
    endpoint = endpoint.lower()

    if 'admin' in endpoint:
        return 'privileged-surface'

    if 'graphql' in endpoint:
        return 'graphql'

    if 'payment' in endpoint or 'billing' in endpoint:
        return 'payment-flow'

    if 'auth' in endpoint or 'login' in endpoint:
        return 'authentication'

    return 'general-api'
