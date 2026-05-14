from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from core.scope import validate_scope
from core.tools import get_tools_with_status
from modules.graphql import graphql_check
from modules.idor import generate_idor_plan
from modules.js_analyzer import analyze_js_url
from modules.nuclei_safe import run_nuclei_safe
from modules.oauth import oauth_check
from modules.recon_pipeline import run_recon_pipeline
from core.report import create_report_from_evidence
from web.agent import parse_command, chat_with_agent
from web.schemas import *

app = FastAPI(title='Legion Dashboard API')
static_dir = Path(__file__).parent / 'static'
app.mount('/static', StaticFiles(directory=static_dir), name='static')

@app.get('/')
def index(): return FileResponse(static_dir / 'index.html')
@app.get('/api/health')
def health(): return {'status': 'ok'}
@app.get('/api/tools')
def tools(): return {'tools': get_tools_with_status()}
@app.get('/api/targets')
def targets():
    r = Path('evidence')
    return {'targets': sorted([p.name for p in r.iterdir() if p.is_dir()]) if r.exists() else []}
@app.get('/api/evidence/{target}')
def evidence(target: str):
    b = Path('evidence') / target
    return {'files': sorted([str(p.relative_to(b)) for p in b.rglob('*') if p.is_file()]) if b.exists() else []}
@app.get('/api/findings/{target}')
def findings(target: str):
    f = Path('evidence') / target / 'ai-analysis'
    return {'findings': sorted([p.name for p in f.glob('*.json')]) if f.exists() else []}

def _v(target, scope):
    try: validate_scope(target, scope)
    except Exception as e: raise HTTPException(status_code=400, detail=str(e))
@app.post('/api/run/recon-pipeline')
def run_recon(req: TargetRequest): _v(req.target, req.scope); return run_recon_pipeline(req.target)
@app.post('/api/run/js-url')
def run_js(req: JSUrlRequest): _v(req.target, req.scope); return analyze_js_url(req.target, req.url, ai_summary=req.ai_summary)
@app.post('/api/run/nuclei-safe')
def run_ns(req: NucleiRequest): _v(req.target, req.scope); return run_nuclei_safe(req.target, req.urls_file)
@app.post('/api/run/graphql-analyze')
def run_gql(req: GraphQLRequest): _v(req.target, req.scope); return graphql_check(req.endpoint, req.target)
@app.post('/api/run/oauth-check')
def run_o(req: OAuthRequest): _v(req.target, req.scope); return oauth_check(req.target, req.url)
@app.post('/api/run/idor-plan')
def run_id(req: IDORPlanRequest): _v(req.target, req.scope); return generate_idor_plan(req.target, req.replay_file)
@app.post('/api/report-auto')
def report_auto(req: ReportRequest): return {'report': create_report_from_evidence(req.finding, req.target)}
@app.post('/api/chat')
def chat(req: ChatRequest):
    _v(req.target, req.scope)
    parsed = parse_command(req.message)
    return {'agent': parsed, 'agent_reply': chat_with_agent(req.message)}
