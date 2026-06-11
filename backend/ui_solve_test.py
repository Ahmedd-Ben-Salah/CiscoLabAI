"""Drive the full solve flow through the real UI: upload -> settings -> solve
-> apply -> re-run Connectivity Test, screenshotting before/after."""
import sys, os
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = os.path.join(os.path.dirname(__file__), 'ui_shots')
os.makedirs(OUT, exist_ok=True)
EXAM = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Examen_RT2_2026_G2 (2).pka'))
KEY = 'AIzaSyAfaM7Lm_8lc9gYcvBniDSjq5wJbsYrneY'

def verify_summary(page):
    page.click('#btn-show-verify')
    page.wait_for_function(
        "document.querySelector('#verify-content') && "
        "!document.querySelector('#verify-content').textContent.includes('Running connectivity')",
        timeout=30000)
    page.wait_for_timeout(800)
    # first line of the panel is the summary banner
    return page.inner_text('#verify-content').split('\n')[0]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1500, 'height': 950})
    page.on('console', lambda m: print('  [console]', m.type, m.text[:160]) if m.type == 'error' else None)
    page.on('download', lambda d: print('  [download] started:', d.suggested_filename))

    print('1. upload'); page.goto('http://localhost:5000', wait_until='networkidle')
    page.set_input_files('input[type=file]', EXAM)
    page.wait_for_selector('#btn-show-verify', timeout=30000)
    page.wait_for_timeout(2000)
    print('   BEFORE summary:', verify_summary(page))

    print('2. settings -> provider/model/key')
    page.click('#btn-settings')
    page.wait_for_selector('#settings-modal:not(.hidden)', timeout=10000)
    page.select_option('#select-provider', 'gemini')
    page.wait_for_timeout(500)
    try:
        page.select_option('#select-model', 'gemini-2.5-flash')
    except Exception:
        print('   (gemini-2.5-flash not in dropdown, using default)')
    page.fill('#input-api-key', KEY)
    page.click('#btn-save-settings')
    page.wait_for_timeout(800)

    print('3. solve (waiting up to 120s)...')
    page.click('#btn-solve')
    outcome = page.wait_for_function(
        """() => {
            const apply = document.getElementById('btn-apply');
            const toasts = [...document.querySelectorAll('.toast, .toast-error, [class*=toast]')]
                .map(t => t.textContent).join(' ');
            if (apply && !apply.disabled) return 'ready';
            if (/failed|error|quota/i.test(toasts)) return 'error:' + toasts.slice(0,160);
            return false;
        }""", timeout=120000).json_value()
    print('   solve outcome:', outcome)
    page.screenshot(path=os.path.join(OUT, '4_solved_configs.png'), full_page=True)

    if str(outcome).startswith('ready'):
        print('4. apply')
        page.click('#btn-apply')
        page.wait_for_timeout(4000)
        print('   AFTER summary:', verify_summary(page))
        page.screenshot(path=os.path.join(OUT, '5_after_connectivity.png'), full_page=True)
    else:
        print('   solve did not complete (likely API quota); skipping apply')

    browser.close()
    print('done; screenshots in', OUT)
