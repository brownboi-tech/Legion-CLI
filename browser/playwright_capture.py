from playwright.sync_api import sync_playwright


class BrowserCapture:
    def capture(self, url: str):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url)
            page.screenshot(path='data/browser_capture.png')
            browser.close()

        print('[+] Browser capture saved')
