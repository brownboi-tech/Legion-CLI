import json
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from modules.evidence_manager import evidence_path, init_evidence_tree
from storage.database import init_db, insert_endpoint, insert_recon_artifact


class BrowserCapture:
    def capture(self, url: str, wait_ms: int = 5000) -> dict:
        parsed = urlparse(url)
        target = parsed.netloc or parsed.path

        init_evidence_tree(target)
        screenshot_file = evidence_path(target, 'screenshots', 'playwright_capture.png')
        requests_file = evidence_path(target, 'requests', 'playwright_requests.json')
        responses_file = evidence_path(target, 'responses', 'playwright_responses.json')
        replay_file = evidence_path(target, 'replay', 'playwright_replay.json')

        req_events: list[dict] = []
        resp_events: list[dict] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            def on_request(req):
                req_events.append({
                    'url': req.url,
                    'method': req.method,
                    'resource_type': req.resource_type,
                    'headers': dict(req.headers),
                })

            def on_response(resp):
                req = resp.request
                resp_events.append({
                    'url': req.url,
                    'method': req.method,
                    'status': resp.status,
                    'resource_type': req.resource_type,
                    'headers': dict(req.headers),
                })

            page.on('request', on_request)
            page.on('response', on_response)
            page.goto(url, wait_until='networkidle')
            page.wait_for_timeout(wait_ms)
            page.screenshot(path=str(screenshot_file), full_page=True)
            browser.close()

        requests_file.write_text(json.dumps(req_events, indent=2))
        responses_file.write_text(json.dumps(resp_events, indent=2))
        replay_file.write_text(json.dumps({'requests': req_events, 'responses': resp_events}, indent=2))

        init_db()
        for ev in resp_events:
            insert_endpoint(target=target, endpoint=ev['url'], source='playwright')
        insert_recon_artifact(target, 'traffic', 'playwright', str(replay_file), len(resp_events))

        print(f'[+] Playwright screenshot: {screenshot_file}')
        print(f'[+] Requests saved: {requests_file}')
        print(f'[+] Responses saved: {responses_file}')
        print(f'[+] Replay bundle: {replay_file}')

        return {'target': target, 'events': len(resp_events), 'replay_file': str(replay_file)}
