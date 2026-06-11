"""Drive the closed-loop Auto-Solve through the real UI and screenshot it."""
import sys, os
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = os.path.join(os.path.dirname(__file__), 'ui_shots')
EXAM = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Examen_RT2_2026_G2 (2).pka'))
KEY = 'AIzaSyAfaM7Lm_8lc9gYcvBniDSjq5wJbsYrneY'

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1500, 'height': 1000})
    page.on('pageerror', lambda e: print('  [pageerror]', str(e)[:200]))

    page.goto('http://localhost:5000', wait_until='networkidle')
    page.set_input_files('input[type=file]', EXAM)
    page.wait_for_selector('#btn-auto-solve', timeout=30000)
    page.wait_for_timeout(1500)

    # settings
    page.click('#btn-settings')
    page.wait_for_selector('#settings-modal:not(.hidden)', timeout=10000)
    page.select_option('#select-provider', 'gemini')
    page.wait_for_timeout(400)
    try:
        page.select_option('#select-model', 'gemini-2.5-flash')
    except Exception:
        pass
    page.fill('#input-api-key', KEY)
    page.click('#btn-save-settings')
    page.wait_for_timeout(600)

    print('clicking Auto-Solve & Verify (closed loop, up to 3 AI passes)...')
    page.click('#btn-auto-solve')
    page.wait_for_function(
        "document.querySelector('#verify-content') && "
        "document.querySelector('#verify-content').textContent.includes('Refinement loop')",
        timeout=300000)
    page.wait_for_timeout(1200)
    page.screenshot(path=os.path.join(OUT, '6_autosolve.png'), full_page=True)

    txt = page.inner_text('#verify-content')
    print('--- verify panel after auto-solve (first 1200 chars) ---')
    print(txt[:1200])
    browser.close()
    print('screenshot: 6_autosolve.png')
