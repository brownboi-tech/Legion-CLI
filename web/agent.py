import os
import re
import json
from openai import OpenAI

ALLOWED_TOOLS = ['run_recon_pipeline','analyze_js_url','run_nuclei_safe','analyze_graphql','check_oauth','import_burp','import_caido','generate_idor_plan','generate_report_from_evidence','traffic_summary','list_targets','list_evidence','list_findings','get_tool_status']


def _mask(text: str) -> str:
    text = re.sub(r'(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-]+', r'\1***MASKED***', text)
    text = re.sub(r'(?i)(cookie\s*:\s*)[^\n]+', r'\1***MASKED***', text)
    text = re.sub(r'(?i)(api[_-]?key|token|secret|sessionid)["\'\s:=]+([A-Za-z0-9._\-]{8,})', r'\1=***MASKED***', text)
    return text


def local_parse(message: str) -> dict:
    t=message.lower()
    if 'recon' in t: return {'intent':'run_recon_pipeline','params':{}}
    if 'analyze' in t and 'js' in t: return {'intent':'analyze_js_url','params':{'url': (re.search(r'https?://\S+',message).group(0) if re.search(r'https?://\S+',message) else '')}}
    if 'nuclei' in t: return {'intent':'run_nuclei_safe','params':{}}
    if 'graphql' in t: return {'intent':'analyze_graphql','params':{}}
    if 'oauth' in t: return {'intent':'check_oauth','params':{'url': (re.search(r'https?://\S+',message).group(0) if re.search(r'https?://\S+',message) else '')}}
    if 'burp' in t and 'import' in t: return {'intent':'import_burp','params':{}}
    if 'caido' in t and 'import' in t: return {'intent':'import_caido','params':{}}
    if 'idor' in t: return {'intent':'generate_idor_plan','params':{}}
    if 'report' in t: return {'intent':'generate_report_from_evidence','params':{}}
    if 'traffic summary' in t: return {'intent':'traffic_summary','params':{}}
    return {'intent':'none','params':{}}


def model_parse(message:str, context:dict):
    if not os.getenv('OPENAI_API_KEY'):
        return local_parse(message)
    client=OpenAI()
    prompt={
      'system':'You are Legion agent for bug bounty only. Output strict JSON: {intent,params,explanation,next_suggestions}. Never ask to hack non-bounty targets.',
      'allowed_tools':ALLOWED_TOOLS,
      'context':context,
      'message':_mask(message)
    }
    r=client.responses.create(model=os.getenv('LEGION_OPENAI_MODEL','gpt-4.1-mini'),input=json.dumps(prompt))
    try:return json.loads(r.output_text)
    except Exception:return local_parse(message)


def terminal_chat():
    print('Legion Agent Chat (type quit)')
    while True:
        msg=input('> ').strip()
        if msg in {'quit','exit'}: break
        print(local_parse(msg))
