"""Standalone check: run the rubric grader against the most recent .pka and print a report.

    python test_rubric.py            # uses newest .pka in uploads/ (or repo root)
"""

import glob
import os
import sys

import pka_parser as p
import topology_extractor as te
import rubric_grader as rg


def _newest_pka():
    candidates = glob.glob('uploads/*.pka') + glob.glob('uploads/*.pkt') \
        + glob.glob('../*.pka')
    if not candidates:
        sys.exit('No .pka found in uploads/ or repo root.')
    return max(candidates, key=os.path.getmtime)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else _newest_pka()
    print(f'File: {path}\n')
    xml = p.decode_pka_bytes(open(path, 'rb').read())

    rubric = rg.extract_rubric(xml)
    print(f'Answer key present : {rubric["present"]}')
    print(f'Graded items       : {len(rubric["items"])}  ({rubric["total_points"]} pts)\n')

    ctx = te.get_full_context(xml)
    report = rg.grade(ctx, xml)
    if not report['present']:
        print('No usable answer key -- fall back to derived oracle.')
        return

    print(f'Verdict   : {report["verdict"]}  ({report["percent"]}%)')
    print(f'Score     : {report["earned_points"]}/{report["possible_points"]} pts '
          f'over {report["auto_checked_items"]} auto-checked items')
    print(f'(of {report["total_graded_items"]} graded items / '
          f'{report["total_graded_points"]} total pts in the rubric)\n')

    fails = report['failures']
    print(f'Failures: {len(fails)}')
    for r in fails[:30]:
        where = r['device'] + (f' {r["interface"]}' if r['interface'] else '')
        print(f'  [{r["points"]}pt] {where} / {r["attribute"]}: '
              f'expected {r["expected"]!r}, got {r["actual"]!r}')
        if r['feedback']:
            print(f'        hint: {r["feedback"][:80]}')


if __name__ == '__main__':
    main()
