import os
import re
import json
from pathlib import Path
from openai import OpenAI

ALLOWED_TOOLS = ['run_recon_pipeline','analyze_js_url','run_nuclei_safe','analyze_graphql','check_oauth','import_burp','import_caido','generate_idor_plan','generate_report_from_evidence','traffic_summary','list_targets','list_evidence','list_findings','get_tool_status']


def _mask(text: str) -> str:
    text = re.sub(r'(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-]+', r'\1***MASKED***', text)
    text = re.sub(r'(?i)(cookie\s*:\s*)[^\n]+', r'\1***MASKED***', text)
    text = re.sub(r'(?i)(api[_-]?key|token|secret|sessionid)["\'\s:=]+([A-Za-z0-9._\-]{8,})', r'\1=***MASKED***', text)
    return text


def _heuristic_next_action(target: str) -> dict:
    base = Path('evidence') / target
    recon_urls = base / 'recon' / 'urls.txt'
    js_findings = base / 'ai-analysis' / 'js_findings.json'
    oauth_findings = base / 'ai-analysis' / 'oauth_analysis.json'
    if not recon_urls.exists():
        return {'intent': 'run_recon_pipeline', 'params': {}, 'explanation': 'No recon URLs found yet; start with recon pipeline.', 'next_suggestions': ['Run recon pipeline first.']}
    if not js_findings.exists():
        return {'intent': 'analyze_js_url', 'params': {}, 'explanation': 'Recon exists; JS intel is next high-value step.', 'next_suggestions': ['Provide a JS URL from urls.txt.']}
    if not oauth_findings.exists():
        return {'intent': 'check_oauth', 'params': {}, 'explanation': 'OAuth review still missing.', 'next_suggestions': ['Provide authorization URL for oauth-check.']}
    return {'intent': 'run_nuclei_safe', 'params': {}, 'explanation': 'Baseline coverage done; run safe nuclei scan next.', 'next_suggestions': ['Provide urls_file path from evidence/<target>/recon/urls.txt']}


def local_parse(message: str, target: str = '') -> dict:
    t = message.lower()
    if any(k in t for k in ['what next', 'next scan', 'next step', 'what should i test next']):
        return _heuristic_next_action(target)
    if 'recon' in t: return {'intent':'run_recon_pipeline','params':{},'explanation':'Recon requested.','next_suggestions':[]}
    if 'analyze' in t and 'js' in t: return {'intent':'analyze_js_url','params':{'url': (re.search(r'https?://\S+',message).group(0) if re.search(r'https?://\S+',message) else '')},'explanation':'JS analysis requested.','next_suggestions':[]}
    if 'nuclei' in t: return {'intent':'run_nuclei_safe','params':{},'explanation':'Nuclei safe scan requested.','next_suggestions':[]}
    if 'graphql' in t: return {'intent':'analyze_graphql','params':{},'explanation':'GraphQL analysis requested.','next_suggestions':[]}
    if 'oauth' in t: return {'intent':'check_oauth','params':{'url': (re.search(r'https?://\S+',message).group(0) if re.search(r'https?://\S+',message) else '')},'explanation':'OAuth check requested.','next_suggestions':[]}
    if 'burp' in t and 'import' in t: return {'intent':'import_burp','params':{},'explanation':'Burp import requested.','next_suggestions':[]}
    if 'caido' in t and 'import' in t: return {'intent':'import_caido','params':{},'explanation':'Caido import requested.','next_suggestions':[]}
    if 'idor' in t: return {'intent':'generate_idor_plan','params':{},'explanation':'IDOR planning requested.','next_suggestions':[]}
    if 'report' in t: return {'intent':'generate_report_from_evidence','params':{},'explanation':'Report generation requested.','next_suggestions':[]}
    if 'traffic summary' in t: return {'intent':'traffic_summary','params':{},'explanation':'Traffic summary requested.','next_suggestions':[]}
    return {'intent':'none','params':{},'explanation':'No actionable command recognized.','next_suggestions':['Ask: what should I test next?']}


def model_parse(message:str, context:dict):
    target = context.get('target', '')
    if not os.getenv('OPENAI_API_KEY'):
        return local_parse(message, target=target)
    client=OpenAI()
    prompt={
      'system':'You are Legion agent for bug bounty only. Output strict JSON: {intent,params,explanation,next_suggestions}. Choose best next safe scan for target context when asked what next.',
      'allowed_tools':ALLOWED_TOOLS,
      'context':context,
      'message':_mask(message)
    }
    r=client.responses.create(model=os.getenv('LEGION_OPENAI_MODEL','gpt-4.1-mini'),input=json.dumps(prompt))
    try:return json.loads(r.output_text)
    except Exception:return local_parse(message, target=target)


def terminal_chat():
    print('Legion Agent Chat (type quit)')
    target=''
    while True:
        msg=input('> ').strip()
        if msg in {'quit','exit'}: break
        if msg.startswith('target '):
            target=msg.split(' ',1)[1].strip();print(f'target set: {target}');continue
        print(local_parse(msg, target=target))
