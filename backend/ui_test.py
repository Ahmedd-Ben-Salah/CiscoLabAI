"""Drive the running CiscoLabAI web UI with a real browser and screenshot it."""
import sys, os, time
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = os.path.join(os.path.dirname(__file__), 'ui_shots')
os.makedirs(OUT, exist_ok=True)
EXAM = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Examen_RT2_2026_G2 (2).pka'))

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1500, 'height': 950})
    page.on('console', lambda m: print('  [console]', m.type, m.text[:200]))
    page.on('pageerror', lambda e: print('  [pageerror]', str(e)[:200]))

    print('1. loading home page...')
    page.goto('http://localhost:5000', wait_until='networkidle')
    page.screenshot(path=os.path.join(OUT, '1_home.png'))

    print('2. uploading exam file...')
    page.set_input_files('input[type=file]', EXAM)
    # wait for the workspace to render (instructions panel / tabs appear)
    page.wait_for_selector('#btn-show-verify', timeout=30000)
    page.wait_for_timeout(2500)
    page.screenshot(path=os.path.join(OUT, '2_uploaded.png'), full_page=True)

    print('3. clicking Connectivity Test tab...')
    page.click('#btn-show-verify')
    # wait until the verify content stops showing the "running" placeholder
    page.wait_for_function(
        "document.querySelector('#verify-content') && "
        "!document.querySelector('#verify-content').textContent.includes('Running connectivity')",
        timeout=30000)
    page.wait_for_timeout(1000)
    page.screenshot(path=os.path.join(OUT, '3_connectivity.png'), full_page=True)

    text = page.inner_text('#verify-content')
    print('--- Connectivity Test panel text (first 1500 chars) ---')
    print(text[:1500])
    badge = page.inner_text('#verify-badge') if page.query_selector('#verify-badge') else ''
    print('--- verify badge:', repr(badge))

    browser.close()
    print('screenshots written to', OUT)
