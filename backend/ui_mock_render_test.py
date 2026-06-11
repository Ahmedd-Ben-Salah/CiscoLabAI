"""Verify the auto-solve UI rendering (renderAutoReport/renderVerify) independent
of the AI API by injecting a realistic mock /api/solve_auto response."""
import sys, os, json
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = os.path.join(os.path.dirname(__file__), 'ui_shots')
EXAM = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Examen_RT2_2026_G2 (2).pka'))

MOCK = {
    "success": True, "verdict": "FAIL", "best_iteration": 2,
    "iterations": [
        {"iteration": 1, "score": 33, "verdict": "FAIL", "num_failures": 4,
         "summary": {"reachable": 45, "unreachable": 10, "errors": 1, "warnings": 0, "incomplete_endpoints": 0}},
        {"iteration": 2, "score": 30, "verdict": "FAIL", "num_failures": 3,
         "summary": {"reachable": 45, "unreachable": 10, "errors": 1, "warnings": 0, "incomplete_endpoints": 0}},
    ],
    "report": {
        "verdict": "FAIL",
        "summary": {"reachable": 45, "unreachable": 10, "uncertain": 45,
                    "incomplete_endpoints": 0, "errors": 1, "warnings": 0, "info": 0},
        "invariants": {"findings": [
            {"severity": "error", "category": "ip", "preexisting": True,
             "message": "Duplicate IP 10.0.20.1 on MLS-D:GigabitEthernet1/0/24 and Edge_router:GigabitEthernet0/0",
             "fix_hint": "Assign distinct IPs; only one device may own an address."},
        ]},
        "reachability": {
            "endpoint_status": [
                {"device": "PC_0", "complete": True, "ip": "172.16.10.2", "mask": "255.255.255.0", "gw": "172.16.10.1", "missing": []},
                {"device": "PC_5", "complete": True, "ip": "172.16.10.55", "mask": "255.255.255.0", "gw": "172.16.10.1", "missing": []},
            ],
            "pairs": [
                {"src": "PC_0", "dst": "PC_2", "reachable": True, "uncertain": True, "reason": "delivered (forward + return verified)"},
                {"src": "PC_0", "dst": "Remote_Admin", "reachable": False, "uncertain": False, "reason": "forward path failed: no route to 30.30.30.30 on MLS-D"},
            ],
        },
    },
    "device_configs": {"MLS-D": {"type": "switch", "commands": ["enable", "configure terminal", "ip routing", "interface vlan 10", "ip address 172.16.10.1 255.255.255.0"], "ip_config": None}},
}

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1500, 'height': 1000})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto('http://localhost:5000', wait_until='networkidle')
    page.set_input_files('input[type=file]', EXAM)
    page.wait_for_selector('#btn-auto-solve', timeout=30000)
    page.wait_for_timeout(1200)

    page.evaluate("(data) => { renderDeviceConfigs(data); switchToTab('verify-tab'); renderAutoReport(data); }", MOCK)
    page.wait_for_timeout(600)
    page.screenshot(path=os.path.join(OUT, '7_autosolve_mock.png'), full_page=True)

    print('JS pageerrors:', errors if errors else 'NONE')
    print('panel text (first 900 chars):')
    print(page.inner_text('#verify-content')[:900])
    browser.close()
