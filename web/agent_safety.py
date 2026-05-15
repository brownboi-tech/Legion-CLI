RISK = {
    'run_recon_pipeline': 'safe',
    'analyze_js_url': 'safe',
    'run_nuclei_safe': 'approval',
    'analyze_graphql': 'safe',
    'check_oauth': 'safe',
    'import_burp': 'safe',
    'import_caido': 'safe',
    'generate_idor_plan': 'safe',
    'generate_report_from_evidence': 'safe',
    'traffic_summary': 'safe',
}

def safety_for(tool_call: dict) -> str:
    return RISK.get(tool_call.get('tool', ''), 'manual')
