"""
oracle.py - Unified verification oracle

Combines the answer-key-independent signals into one report:
  - network_simulator.simulate()  -> host-to-host reachability + endpoint config
  - invariants.full_invariants()  -> protocol consistency (VLAN/trunk/EtherChannel/
                                     STP/HSRP/DHCP/OSPF)

This is the single entry point /api/verify calls. When an embedded grading rubric
is added later it slots in here as an extra, higher-precision signal.
"""

from network_simulator import simulate
from invariants import full_invariants
from objective_tests import objective_tests


def verify(context):
    sim = simulate(context)
    inv = full_invariants(context)
    obj = objective_tests(context)

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

    # A simple top-level verdict for the UI banner. A failed professor test is a
    # hard fail — that is the actual success criterion for the lab.
    if obj['failed'] > 0 or summary.get('errors', 0) > 0 or summary.get('unreachable', 0) > 0:
        verdict = 'FAIL'
    elif summary.get('warnings', 0) > 0 or summary.get('uncertain', 0) > 0 \
            or summary.get('incomplete_endpoints', 0) > 0:
        verdict = 'WARN'
    else:
        verdict = 'PASS'

    return {
        'verdict': verdict,
        'summary': summary,
        'objective_tests': obj,
        'reachability': sim,
        'invariants': inv,
    }
