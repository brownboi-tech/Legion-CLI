import os,re
from openai import OpenAI

def parse_command(message:str)->dict:
 t=message.lower()
 if 'recon' in t:return {'action':'recon-pipeline'}
 if 'js' in t and 'http' in t:return {'action':'js-url','url':(re.search(r'https?://\S+',message) or [''])[0]}
 if 'nuclei' in t:return {'action':'nuclei-safe'}
 if 'graphql' in t:return {'action':'graphql-analyze'}
 if 'oauth' in t:return {'action':'oauth-check','url':(re.search(r'https?://\S+',message) or [''])[0]}
 if 'idor' in t:return {'action':'idor-plan'}
 if 'report' in t:return {'action':'report-auto'}
 return {'action':'none'}

def chat_with_agent(message:str)->str:
 if not os.getenv('OPENAI_API_KEY'): return 'OPENAI_API_KEY missing. Parsed command only mode.'
 c=OpenAI();r=c.responses.create(model='gpt-4.1-mini',input=f'Interpret this pentest dashboard request safely: {message}')
 return r.output_text.strip()
