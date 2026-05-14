import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from storage.database import init_db, insert_endpoint, insert_recon_artifact


class BrowserCapture:
    def capture(self, url: str, output_dir: str = 'data/traffic', wait_ms: int = 5000) -> dict:
        parsed = urlparse(url)
        target = parsed.netloc or parsed.path

        target_dir = Path(output_dir) / target
        target_dir.mkdir(parents=True, exist_ok=True)

        screenshot_file = target_dir / 'screenshot.png'
        traffic_file = target_dir / 'playwright_traffic.json'

        traffic_events: list[dict] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            def on_response(resp):
                req = resp.request
                event = {
                    'url': req.url,
                    'method': req.method,
                    'status': resp.status,
                    'resource_type': req.resource_type,
                    'headers': dict(req.headers),
                }
                traffic_events.append(event)

            page.on('response', on_response)
            page.goto(url, wait_until='networkidle')
            page.wait_for_timeout(wait_ms)
            page.screenshot(path=str(screenshot_file), full_page=True)

            browser.close()

        traffic_file.write_text(json.dumps(traffic_events, indent=2))

        init_db()
        for ev in traffic_events:
            insert_endpoint(target=target, endpoint=ev['url'], source='playwright')
        insert_recon_artifact(
            target=target,
            phase='traffic',
            tool='playwright',
            file_path=str(traffic_file),
            line_count=len(traffic_events),
        )

        print(f'[+] Playwright screenshot: {screenshot_file}')
        print(f'[+] Playwright traffic: {traffic_file}')

        return {
            'target': target,
            'screenshot': str(screenshot_file),
            'traffic_file': str(traffic_file),
            'events': len(traffic_events),
        }
