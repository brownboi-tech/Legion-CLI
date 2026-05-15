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
from modules.scope_builder import create_scope_from_text
from modules.replay_engine import replay_diff
from web.agent import model_parse
from web.schemas import *
from web.agent_memory import load_session, save_session
from web.agent_safety import safety_for
from web.agent_tools import dispatch, missing_params, required_for

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
    r = Path('evidence'); return {'targets': sorted([p.name for p in r.iterdir() if p.is_dir()]) if r.exists() else []}
@app.get('/api/evidence/{target}')
def evidence(target: str):
    b = Path('evidence') / target; return {'files': sorted([str(p.relative_to(b)) for p in b.rglob('*') if p.is_file()]) if b.exists() else []}
@app.get('/api/findings/{target}')
def findings(target: str):
    f = Path('evidence') / target / 'ai-analysis'; return {'findings': sorted([p.name for p in f.glob('*.json')]) if f.exists() else []}

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
@app.post('/api/run/replay-diff')
def run_replay_diff(req: ReplayDiffRequest): _v(req.target, req.scope); return replay_diff(req.target, req.request_file, req.session_a, req.session_b)
@app.post('/api/report-auto')
def report_auto(req: ReportRequest): return {'report': create_report_from_evidence(req.finding, req.target)}
@app.post('/api/scope/from-chat')
def scope_from_chat(req: ScopeFromChatRequest): return create_scope_from_text(req.program, req.message, save=True)

@app.post('/api/chat')
def chat(req: ChatRequest):
    _v(req.target, req.scope)
    sid, mem = load_session(req.session_id)
    mem['current_target'] = req.target
    mem['current_scope'] = req.scope

    parsed = model_parse(req.message, {'target': req.target, 'scope': req.scope})
    intent = parsed.get('intent', 'none')
    params = parsed.get('params', {}) or {}
    params.setdefault('target', req.target)

    tool_call = {'tool': intent, 'params': params, 'required_parameters': required_for(intent)}
    safety = safety_for(tool_call)

    missing = missing_params(intent, params) if intent != 'none' else []
    if missing:
        mem['messages'].append({'role': 'user', 'content': req.message})
        save_session(sid, mem)
        return {
            'assistant_message': f"I need these fields before running {intent}: {', '.join(missing)}",
            'intent': intent,
            'tool_call': tool_call,
            'safety_level': safety,
            'confirmation_required': False,
            'result': None,
            'next_suggestions': [f"Provide: {m}" for m in missing],
            'session_id': sid,
        }

    confirm = safety == 'approval'
    result = None
    if intent and intent != 'none' and safety == 'safe':
        result = dispatch(intent, params)
    elif confirm:
        mem['pending_confirmation'] = {'tool': intent, 'params': params, 'preview': f"{intent} with {params}"}

    mem['messages'].append({'role': 'user', 'content': req.message})
    mem['last_results'] = result or mem.get('last_results', {})
    save_session(sid, mem)

    return {
        'assistant_message': parsed.get('explanation', 'Ready.'),
        'intent': intent,
        'tool_call': tool_call,
        'safety_level': safety,
        'confirmation_required': confirm,
        'result': result,
        'next_suggestions': parsed.get('next_suggestions', []),
        'session_id': sid,
    }

@app.post('/api/chat/confirm')
def chat_confirm(req: ChatConfirmRequest):
    sid, mem = load_session(req.session_id)
    pending = mem.get('pending_confirmation')
    if not pending:
        return {'assistant_message':'No pending confirmation.', 'result':None}
    result = dispatch(pending['tool'], pending['params'])
    mem['pending_confirmation'] = None
    mem['last_results'] = result
    save_session(sid, mem)
    return {'assistant_message':'Approved action executed.', 'result':result, 'session_id':sid}
