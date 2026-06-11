"""
objective_tests.py - Run the professor's intended tests against the solution

Cisco lab instructions usually state the success criteria inline — "Vérifier que
le PC remote_admin peut accéder au réseau", "PC1 doit pinguer le serveur",
"vérifier la connectivité inter-VLAN". Before we hand a solution to the student,
we extract those criteria and actually test them on the (solved) network with the
control-plane simulator.

If the instructions contain no explicit connectivity test, we fall back to
auto-generated connectivity tests (every host -> each server, or cross-subnet
host pairs) so there is always a meaningful pass/fail gate.

No LLM call is needed — extraction is heuristic and the tests run on the
deterministic simulator, so this works offline.
"""

import re
import html
from network_simulator import build_model, can_reach


# Verification-intent keywords (French + English).
_VERIFY_KW = re.compile(
    r'(v[ée]rifi|ping|connectivit|connectivity|reach|atteind|acc[eé]d|joindre|'
    r'\bjoin\b|test\b|doit\s+ping|peut\s+ping)', re.I)


def _norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def _strip_html(instr):
    txt = re.sub(r'<[^>]+>', ' ', instr or '')
    return html.unescape(re.sub(r'\s+', ' ', txt))


def _sentences(text):
    # split on sentence terminators and newlines/bullets
    return [s for s in re.split(r'(?<=[.!?:;])\s+|\n|•|ü', text) if s.strip()]


def extract_tests(instructions, device_names):
    """Parse instructions into concrete connectivity tests.

    Returns list of {kind:'ping'|'reach_network', src, dst?, raw}.
    Device matching is token-exact (normalized) to avoid false hits on short
    names like R1/R2; quoted names and underscores are handled.
    """
    text = _strip_html(instructions)
    norm_to_name = {}
    for n in device_names:
        nn = _norm(n)
        if len(nn) >= 2:
            norm_to_name[nn] = n

    tests, seen = [], set()
    for sent in _sentences(text):
        if not _VERIFY_KW.search(sent):
            continue
        # token-exact device matches (keep order, dedup)
        present = []
        for tok in re.findall(r"[A-Za-z0-9_\-]+", sent):
            name = norm_to_name.get(_norm(tok))
            if name and name not in present:
                present.append(name)

        if len(present) >= 2:
            for i in range(len(present)):
                for j in range(i + 1, len(present)):
                    key = ('ping', present[i], present[j])
                    rkey = ('ping', present[j], present[i])
                    if key in seen or rkey in seen:
                        continue
                    seen.add(key)
                    tests.append({'kind': 'ping', 'src': present[i],
                                  'dst': present[j], 'raw': sent.strip()[:160]})
        elif len(present) == 1:
            key = ('reach_network', present[0], None)
            if key not in seen:
                seen.add(key)
                tests.append({'kind': 'reach_network', 'src': present[0],
                              'raw': sent.strip()[:160]})
        # sentences with verify-intent but no named device are covered by the
        # auto connectivity fallback, so we don't emit a test for them here.
    return tests


def _auto_tests(model):
    """Connectivity tests when the instructions name none."""
    eps = list(model['endpoints'].keys())
    servers = [n for n, e in model['endpoints'].items() if e.get('kind') == 'server']
    tests = []
    if servers:
        for e in eps:
            for s in servers:
                if e != s:
                    tests.append({'kind': 'ping', 'src': e, 'dst': s,
                                  'raw': 'auto: every host should reach the server'})
    else:
        for i in range(len(eps)):
            for j in range(i + 1, len(eps)):
                tests.append({'kind': 'ping', 'src': eps[i], 'dst': eps[j],
                              'raw': 'auto: end-to-end connectivity'})
    return tests


def _run(model, tests):
    eps = set(model['endpoints'].keys())
    servers = [n for n, e in model['endpoints'].items() if e.get('kind') == 'server']
    results = []
    for t in tests:
        src = t.get('src')
        if src not in eps:
            results.append({**t, 'status': 'skipped',
                            'detail': f"can only test from end devices, not {src}"})
            continue
        if t['kind'] == 'ping':
            dst = t.get('dst')
            if dst not in eps:
                results.append({**t, 'status': 'skipped',
                                'detail': f"{dst} is not an end device"})
                continue
            r = can_reach(model, src, dst)
            results.append({**t, 'status': 'pass' if r['reachable'] else 'fail',
                            'detail': r['reason']})
        elif t['kind'] == 'reach_network':
            # "can access the network" -> must reach at least one server, else any
            # host on a different subnet.
            targets = [s for s in servers if s != src] or [e for e in eps if e != src]
            ok, detail = False, 'no reachable target found'
            for tg in targets:
                r = can_reach(model, src, tg)
                if r['reachable']:
                    ok, detail = True, f"reaches {tg}"
                    break
                detail = r['reason']
            results.append({**t, 'dst': 'network', 'status': 'pass' if ok else 'fail',
                            'detail': detail})
    return results


def objective_tests(context):
    """
    Top-level: returns the professor's tests (or auto fallback) run on the
    current network.

    {
      'source': 'instructions' | 'auto',
      'total', 'passed', 'failed', 'skipped',
      'results': [ {kind, src, dst, status, detail, raw}, ... ],
    }
    """
    model = build_model(context)
    device_names = [d['name'] for d in context.get('devices', []) if d.get('name')]

    tests = extract_tests(context.get('instructions', ''), device_names)
    source = 'instructions'
    # Keep only runnable tests (between end devices); if none remain, fall back.
    runnable = [t for t in tests
                if t.get('src') in model['endpoints']
                and (t['kind'] != 'ping' or t.get('dst') in model['endpoints'])]
    if not runnable:
        source = 'auto'
        tests = _auto_tests(model)
    else:
        tests = runnable

    results = _run(model, tests)
    passed = sum(1 for r in results if r['status'] == 'pass')
    failed = sum(1 for r in results if r['status'] == 'fail')
    skipped = sum(1 for r in results if r['status'] == 'skipped')
    return {'source': source, 'total': len(results), 'passed': passed,
            'failed': failed, 'skipped': skipped, 'results': results}
