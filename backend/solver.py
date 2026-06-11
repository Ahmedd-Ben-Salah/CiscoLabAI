"""
solver.py - Closed-loop refinement: solve -> apply -> verify -> re-solve

The single-shot solver generates config once and hopes it's right. This loop
turns the verification oracle into a feedback signal:

    1. Solve the lab (LLM).
    2. Apply the config in-memory and VERIFY it (network_simulator + invariants).
    3. If the oracle reports failures, feed the SPECIFIC failures back to the LLM
       and ask it to fix only those.
    4. Repeat, applying each fix onto the running network (so the LLM always sees
       the real current state), until the network verifies clean or we hit the
       iteration cap. Keep the best-scoring result.

Application is additive, so each round builds on the last. The returned
modified_xml is ready to re-encode and download.
"""

from ai_engine import build_prompt, call_ai, parse_ai_response, SYSTEM_PROMPT
from config_injector import apply_solution_to_xml
from oracle import verify
from topology_extractor import get_full_context


def _score(report, preexisting=None):
    """Lower is better. Hard failures (unreachable, config errors) weigh most.
    Pre-existing professor issues are excluded — the solve isn't graded on them."""
    preexisting = preexisting or set()
    s = report['summary']
    findings = report['invariants']['findings']
    err = sum(1 for f in findings if f['severity'] == 'error' and _finding_key(f) not in preexisting)
    warn = sum(1 for f in findings if f['severity'] == 'warning' and _finding_key(f) not in preexisting)
    # A failed professor test is the heaviest signal — it's the lab's actual goal.
    tests_failed = report.get('objective_tests', {}).get('failed', 0)
    return (tests_failed * 5
            + s.get('unreachable', 0) * 3
            + err * 4
            + s.get('incomplete_endpoints', 0) * 2
            + warn)


def _finding_key(f):
    return (f['category'], f['message'])


def _failures(report, preexisting=None):
    """Concise, de-duplicated list of what's still wrong — fed back to the LLM.
    Pre-existing invariant issues (the professor's, present before solving) are
    excluded: the loop is additive and must not overwrite them to 'fix' them."""
    preexisting = preexisting or set()
    lines = []

    # The professor's explicit tests come first — they are the lab's success
    # criteria and what the student will actually be graded on.
    for t in report.get('objective_tests', {}).get('results', []):
        if t.get('status') == 'fail':
            dst = t.get('dst', 'network')
            lines.append(f"PROFESSOR TEST FAILS: {t['src']} must reach {dst} "
                         f"(\"{t.get('raw', '')[:80]}\") — {t['detail']}")

    reach = report['reachability']

    for e in reach['endpoint_status']:
        if not e['complete']:
            lines.append(f"{e['device']} is missing: {', '.join(e['missing'])}")

    # Reachability failures often share one root cause; collapse by reason.
    by_reason = {}
    for p in reach['pairs']:
        if not p['reachable']:
            by_reason.setdefault(p['reason'], []).append(f"{p['src']}->{p['dst']}")
    for reason, pairs in by_reason.items():
        sample = ', '.join(pairs[:3]) + ('' if len(pairs) <= 3 else f" (+{len(pairs)-3} more)")
        lines.append(f"connectivity fails ({sample}): {reason}")

    for f in report['invariants']['findings']:
        if f['severity'] in ('error', 'warning') and _finding_key(f) not in preexisting:
            hint = f" (fix: {f['fix_hint']})" if f.get('fix_hint') else ''
            lines.append(f"[{f['severity']}] {f['message']}{hint}")

    return lines


def _build_refine_prompt(context, failures, mode, remarks, audit_report):
    """Reuse the standard prompt (with current state) + a verifier-feedback block."""
    base = build_prompt(context.get('instructions', ''), context, mode, remarks,
                        audit_report=audit_report)
    fb = [
        "",
        "=== AUTOMATED VERIFIER FEEDBACK (authoritative) ===",
        "A deterministic network simulator applied your previous configuration and",
        "found the problems below. The CURRENT STATE above already reflects what you",
        "configured. Fix these by ADDING the missing configuration:",
        "",
    ]
    fb += [f"  - {line}" for line in failures]
    fb += [
        "",
        "RULES FOR THIS FIX ROUND:",
        "- Add only the MISSING configuration needed to resolve the problems above.",
        "- Every pre-existing IP address, VLAN, and OSPF setting the lab already had",
        "  is IMMUTABLE — never change or overwrite an address the professor set.",
        "- Common additive fixes: create a missing SVI, enable 'ip routing', add an",
        "  OSPF 'network' statement, add a static/default route, allow a VLAN on a",
        "  trunk, add 'ip helper-address'.",
        "- If a problem is caused by a pre-existing conflict you cannot resolve",
        "  additively, leave it — do NOT overwrite existing config to work around it.",
        "",
        "Respond with ONLY valid JSON {devices:{...}}. Include only devices that need changes.",
    ]
    return base + "\n".join(fb)


def _merge_device_view(view, solution):
    """Accumulate per-device config across iterations for display."""
    for name, cfg in solution.get('devices', {}).items():
        entry = view.setdefault(name, {'type': cfg.get('type', 'unknown'),
                                       'commands': [], 'ip_config': None})
        for c in cfg.get('commands', []):
            if c not in entry['commands']:
                entry['commands'].append(c)
        if cfg.get('ip_config'):
            entry['ip_config'] = cfg['ip_config']
    return view


def solve_with_refinement(provider, api_key, model, xml_string, context, audit_report,
                          mode='config_only', remarks='', max_iters=3, on_progress=None):
    """
    Run the closed loop. Returns:
      {
        'modified_xml', 'report', 'score', 'iteration',  # best result
        'config_results',                                # final-iter apply results
        'device_view',                                   # merged per-device config
        'history': [ {iteration, score, verdict, summary, num_failures}, ... ],
      }
    """
    history = []
    device_view = {}
    xml_current = xml_string
    ctx_current = context
    best = None
    prev_failures = []

    # Baseline: issues already present in the UNSOLVED lab. These are the
    # professor's pre-existing config (e.g. a duplicate IP they left in) — the
    # additive loop must not try to "fix" them by overwriting anchors, so we
    # exclude them from the feedback and surface them separately for the human.
    baseline = verify(context)
    preexisting = {_finding_key(f) for f in baseline['invariants']['findings']
                   if f['severity'] in ('error', 'warning')}

    for i in range(max_iters):
        if i == 0:
            prompt = build_prompt(ctx_current.get('instructions', ''), ctx_current,
                                  mode, remarks, audit_report=audit_report)
        else:
            prompt = _build_refine_prompt(ctx_current, prev_failures, mode, remarks, audit_report)

        try:
            raw = call_ai(provider, api_key, model, SYSTEM_PROMPT, prompt)
        except Exception as e:
            # An AI failure mid-loop (e.g. rate limit / quota) shouldn't throw away
            # a good earlier iteration — keep the best result we already have.
            if best is not None:
                history.append({'iteration': i + 1, 'score': None, 'verdict': 'ERROR',
                                'summary': {}, 'num_failures': None,
                                'error': f'AI call failed: {e}'})
                break
            raise  # nothing salvageable yet → surface the error
        solution = parse_ai_response(raw)
        _merge_device_view(device_view, solution)

        # Apply this round's delta onto the running network. Guardrails stay ON
        # every round: pre-existing IPs/VLANs the professor set are immutable and
        # must never be overwritten — the loop only ever ADDS config.
        xml_new, config_results = apply_solution_to_xml(
            xml_current, solution, ctx_current['devices'], audit_report)
        report = verify(get_full_context(xml_new))
        # Tag which invariant findings were already in the unsolved lab.
        for f in report['invariants']['findings']:
            f['preexisting'] = _finding_key(f) in preexisting
        score = _score(report, preexisting)
        failures = _failures(report, preexisting)

        rec = {'iteration': i + 1, 'score': score, 'verdict': report['verdict'],
               'summary': report['summary'], 'num_failures': len(failures)}
        history.append(rec)
        if on_progress:
            on_progress(rec)

        if best is None or score < best['score']:
            best = {'modified_xml': xml_new, 'report': report, 'score': score,
                    'iteration': i + 1, 'config_results': config_results}

        prev_failures = failures
        if score == 0 or not failures or i == max_iters - 1:
            break

        # Next round the LLM sees the real, partially-solved state.
        xml_current = xml_new
        ctx_current = get_full_context(xml_new)

    best['history'] = history
    best['device_view'] = device_view
    return best
