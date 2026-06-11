"""
oracle.py - Unified verification oracle

Combines the answer-key-independent signals into one report:
  - network_simulator.simulate()  -> host-to-host reachability + endpoint config
  - invariants.full_invariants()  -> protocol consistency (VLAN/trunk/EtherChannel/
                                     STP/HSRP/DHCP/OSPF)
  - objective_tests.objective_tests() -> the professor's success criteria

When the raw lab XML is passed in, the .pka's own embedded answer key
(rubric_grader) is added as an extra, higher-precision signal. It is an
accelerator, never a replacement: locked/obfuscated/.pkt files have no embedded
answers and `rubric['present']` is False, leaving the derived oracle untouched.

This is the single entry point /api/verify calls.
"""

from network_simulator import simulate
from invariants import full_invariants
from objective_tests import objective_tests
from rubric_grader import grade as grade_rubric


def verify(context, xml=None):
    sim = simulate(context)
    inv = full_invariants(context)
    obj = objective_tests(context)
    rubric = grade_rubric(context, xml) if xml else {'present': False}

    summary = dict(sim.get('summary', {}))
    summary.update({
        'errors': inv['summary']['errors'],
        'warnings': inv['summary']['warnings'],
        'info': inv['summary']['info'],
        'tests_passed': obj['passed'],
        'tests_failed': obj['failed'],
        'tests_total': obj['total'],
        'tests_source': obj['source'],
    })

    rubric_fails = 0
    if rubric.get('present'):
        rubric_fails = len(rubric['failures'])
        summary['rubric_percent'] = rubric['percent']
        summary['rubric_failures'] = rubric_fails
        summary['rubric_checked'] = rubric['auto_checked_items']

    # A simple top-level verdict for the UI banner. A failed professor test is a
    # hard fail — that is the actual success criterion for the lab. A mismatch
    # against the embedded answer key is at least a warning (the auto-checkable
    # subset is narrow, so it never on its own escalates to a hard FAIL).
    if obj['failed'] > 0 or summary.get('errors', 0) > 0 or summary.get('unreachable', 0) > 0:
        verdict = 'FAIL'
    elif summary.get('warnings', 0) > 0 or summary.get('uncertain', 0) > 0 \
            or summary.get('incomplete_endpoints', 0) > 0 or rubric_fails > 0:
        verdict = 'WARN'
    else:
        verdict = 'PASS'

    return {
        'verdict': verdict,
        'summary': summary,
        'objective_tests': obj,
        'reachability': sim,
        'invariants': inv,
        'rubric': rubric,
    }
