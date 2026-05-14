import os
import re
from openai import OpenAI

ACTION_MAP = {
    'recon-pipeline': {'safety_level': 'safe', 'route': '/api/run/recon-pipeline', 'required_parameters': ['target', 'scope']},
    'js-url': {'safety_level': 'safe', 'route': '/api/run/js-url', 'required_parameters': ['target', 'scope', 'url']},
    'nuclei-safe': {'safety_level': 'approval', 'route': '/api/run/nuclei-safe', 'required_parameters': ['target', 'scope', 'urls_file']},
    'graphql-analyze': {'safety_level': 'safe', 'route': '/api/run/graphql-analyze', 'required_parameters': ['target', 'scope', 'endpoint']},
    'oauth-check': {'safety_level': 'safe', 'route': '/api/run/oauth-check', 'required_parameters': ['target', 'scope', 'url']},
    'idor-plan': {'safety_level': 'safe', 'route': '/api/run/idor-plan', 'required_parameters': ['target', 'scope', 'replay_file']},
    'report-auto': {'safety_level': 'safe', 'route': '/api/report-auto', 'required_parameters': ['target', 'finding']},
    'manual-checklist': {'safety_level': 'manual', 'route': None, 'required_parameters': []},
    'none': {'safety_level': 'safe', 'route': None, 'required_parameters': []},
}


def parse_command(message: str) -> dict:
    text = message.lower().strip()
    action = 'none'
    explanation = 'No actionable command recognized.'

    if any(x in text for x in ['sqlmap', 'xss payload spray', 'destructive', 'exploit now']):
        action = 'manual-checklist'
        explanation = 'Requested action is high-risk/manual. Returning checklist-only guidance.'
    elif 'recon' in text:
        action = 'recon-pipeline'; explanation = 'Detected recon request.'
    elif 'js' in text and 'http' in text:
        action = 'js-url'; explanation = 'Detected JS URL analysis request.'
    elif 'nuclei' in text:
        action = 'nuclei-safe'; explanation = 'Detected nuclei safe scan request.'
    elif 'graphql' in text:
        action = 'graphql-analyze'; explanation = 'Detected GraphQL analysis request.'
    elif 'oauth' in text:
        action = 'oauth-check'; explanation = 'Detected OAuth URL check request.'
    elif 'idor' in text:
        action = 'idor-plan'; explanation = 'Detected IDOR planning request.'
    elif 'report' in text:
        action = 'report-auto'; explanation = 'Detected auto-report generation request.'

    meta = ACTION_MAP[action]
    return {
        'parsed_action': action,
        'safety_level': meta['safety_level'],
        'suggested_api_route': meta['route'],
        'required_parameters': meta['required_parameters'],
        'explanation': explanation,
        'extracted_url': (re.search(r'https?://\S+', message).group(0) if re.search(r'https?://\S+', message) else ''),
    }


def chat_with_agent(message: str) -> str:
    if not os.getenv('OPENAI_API_KEY'):
        return 'OPENAI_API_KEY missing. Using local parser response.'
    client = OpenAI()
    resp = client.responses.create(model='gpt-4.1-mini', input=f'Provide concise operator guidance for this dashboard request: {message}')
    return resp.output_text.strip()
