"""
rubric_grader.py - Grade a solved network against the .pka's own embedded answer key.

Every Packet Tracer activity (.pka) ships with the instructor's grading tree inside
the `<INITIALSETUP>` element. Each graded leaf is:

    Network > <DeviceName> > [Ports > <Interface> >] <Attribute>

and carries, on its <NAME> tag:
    nodeValue          = the correct (expected) value
    variableEnabled    = "true" when the item is actually graded
    incorrectFeedback  = the instructor's hint shown on a wrong answer
with a sibling <POINTS> = the weight.

This is a *high-precision* oracle: when the answer key is present (not stripped,
not obfuscated) it tells us the exact expected value and weight for each item, so
we can produce a weighted score and per-item pass/fail with the professor's own
feedback. It is an accelerator layered on top of the answer-key-independent oracle
(simulator + invariants + objective tests), never a replacement -- locked/obfuscated
/.pkt files have no embedded answers and fall back to the derived oracle.

Only attributes we can resolve unambiguously from the running-config are auto-checked
(hostname + per-interface IP/mask today); everything else is reported as `checkable=False`
so we never emit a false negative for something we simply didn't model yet.
"""

import ipaddress
import re
import xml.etree.ElementTree as ET


# Values that are just defaults / "unset" -- a leaf carrying one of these is not a
# real answer the student has to produce, so it is excluded from the answer key.
_DEFAULT_VALUES = {
    '', '0', '0.0.0.0', '::', '0.0.0.0/0', 'false',
    'autoNegotiate=true bandwidth=1000000',
    'autoNegotiate=true isFullDuplex=true',
}

# Attributes this module knows how to read back out of a device running-config.
# Anything outside this set is parsed into the rubric but marked not auto-checkable.
ATTR_HOSTNAME = 'Host Name'
ATTR_IP = 'IP Address'
ATTR_MASK = 'Subnet Mask'
_CHECKABLE_ATTRS = {ATTR_HOSTNAME, ATTR_IP, ATTR_MASK}


def _is_meaningful(value):
    v = (value or '').strip()
    if v in _DEFAULT_VALUES:
        return False
    if v.startswith('autoNegotiate'):
        return False
    return True


def extract_rubric(xml):
    """Parse the embedded grading tree.

    Returns a dict:
        {
          'present': bool,                # answer key found and has real values
          'items': [ {device, interface, attribute, path, expected, points, feedback} ],
          'total_points': int,            # sum of points over meaningful graded items
        }
    Items with default/blank expected values are dropped -- they are not things the
    student has to configure.
    """
    start = xml.find('<INITIALSETUP>')
    end = xml.find('</INITIALSETUP>')
    if start == -1 or end == -1:
        return {'present': False, 'items': [], 'total_points': 0}

    block = xml[start:end + len('</INITIALSETUP>')]
    try:
        root = ET.fromstring(block)
    except ET.ParseError:
        return {'present': False, 'items': [], 'total_points': 0}

    items = []

    def walk(node, path):
        name_el = node.find('NAME')
        name = (name_el.text or '').strip() if name_el is not None else ''
        new_path = path + [name] if name else path

        if name_el is not None:
            points_el = node.find('POINTS')
            points = (points_el.text or '').strip() if points_el is not None else ''
            enabled = name_el.get('variableEnabled') == 'true'
            expected = (name_el.get('nodeValue') or '').strip()
            if enabled and points not in ('', '0') and _is_meaningful(expected):
                # path = ['Network', device, ... , attribute]
                device = new_path[1] if len(new_path) > 1 else ''
                attribute = new_path[-1]
                interface = None
                if 'Ports' in new_path:
                    pi = new_path.index('Ports')
                    if pi + 1 < len(new_path) - 1:  # there is an iface between Ports and attr
                        interface = new_path[pi + 1]
                try:
                    pts = int(points)
                except ValueError:
                    pts = 1
                items.append({
                    'device': device,
                    'interface': interface,
                    'attribute': attribute,
                    'path': ' > '.join(new_path),
                    'expected': expected,
                    'points': pts,
                    'feedback': (name_el.get('incorrectFeedback') or '').strip(),
                })

        for child in node.findall('NODE'):
            walk(child, new_path)

    for top in root.findall('NODE'):
        walk(top, [])

    total = sum(it['points'] for it in items)
    return {'present': bool(items), 'items': items, 'total_points': total}


# ── reading actual values back out of the solved device ────────────────────────
#
# Interface NAMEs are blank in the extracted context, so we cannot match a rubric
# item to a specific port by name. Instead we collect every address actually
# configured on the device (from the parsed interface list *and* the running-config)
# and check membership. IPs are globally unique in a correct lab, so "device X has
# the expected IP configured somewhere" is a reliable per-device check; masks are
# matched the same way (slightly weaker, but it is the most precision the blank
# names allow).

def _norm_v6(addr):
    """Canonical IPv6 string (case- and zero-compression-insensitive), or None."""
    try:
        return str(ipaddress.IPv6Address(addr.split('/')[0].strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def _device_index(device):
    """Return {'hostname', 'ipv4'(set), 'masks'(set), 'ipv6'(set of canonical)}."""
    ipv4, masks, ipv6 = set(), set(), set()
    for it in device.get('interfaces') or []:
        if it.get('ip'):
            ipv4.add(it['ip'].strip())
        if it.get('mask'):
            masks.add(it['mask'].strip())
        if it.get('ipv6'):
            v6 = _norm_v6(it['ipv6'])
            if v6:
                ipv6.add(v6)

    rc = device.get('running_config', '') or ''
    for m in re.finditer(r'ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', rc):
        ipv4.add(m.group(1))
        masks.add(m.group(2))
    for m in re.finditer(r'ipv6 address (\S+)', rc, re.I):
        v6 = _norm_v6(m.group(1))
        if v6:
            ipv6.add(v6)

    host = None
    mh = re.search(r'(?m)^\s*hostname\s+(\S+)', rc)
    if mh:
        host = mh.group(1)
    return {'hostname': host, 'ipv4': ipv4, 'masks': masks, 'ipv6': ipv6}


def _resolve_actual(item, idx):
    """Resolve a rubric item against a device index. Returns (actual, ok, checkable)."""
    attr = item['attribute']
    if attr not in _CHECKABLE_ATTRS:
        return None, False, False

    expected = item['expected']

    if attr == ATTR_HOSTNAME:
        actual = idx.get('hostname')
        return actual, (actual == expected), True

    if attr == ATTR_MASK:
        masks = idx['masks']
        ok = expected in masks
        return (expected if ok else (', '.join(sorted(masks)) or None)), ok, True

    # ATTR_IP -- IPv4 or IPv6 depending on the expected literal
    if ':' in expected:
        want = _norm_v6(expected)
        ok = want is not None and want in idx['ipv6']
        return (expected if ok else (', '.join(sorted(idx['ipv6'])) or None)), ok, True
    ipv4 = idx['ipv4']
    ok = expected in ipv4
    return (expected if ok else (', '.join(sorted(ipv4)) or None)), ok, True


def grade(context, xml):
    """Grade the solved `context` network against the .pka's embedded answer key.

    Returns a report dict; `present=False` when there is no usable answer key
    (so callers can silently fall back to the derived oracle).
    """
    rubric = extract_rubric(xml)
    if not rubric['present']:
        return {'present': False}

    # index every device once
    dev_index = {}
    for d in context.get('devices', []):
        name = d.get('name')
        if name:
            dev_index[name] = _device_index(d)

    results = []
    earned = possible = 0          # over auto-checkable items only
    checkable_count = 0
    for it in rubric['items']:
        idx = dev_index.get(it['device'])
        if idx is None:
            actual, ok, checkable = None, False, False
        else:
            actual, ok, checkable = _resolve_actual(it, idx)
        if checkable:
            checkable_count += 1
            possible += it['points']
            if ok:
                earned += it['points']
        results.append({
            'device': it['device'],
            'interface': it['interface'],
            'attribute': it['attribute'],
            'expected': it['expected'],
            'actual': actual,
            'ok': ok,
            'checkable': checkable,
            'points': it['points'],
            'feedback': it['feedback'],
        })

    percent = round(100.0 * earned / possible, 1) if possible else None
    failures = [r for r in results if r['checkable'] and not r['ok']]

    if percent is None:
        verdict = 'UNKNOWN'
    elif percent >= 100:
        verdict = 'PASS'
    elif percent >= 50:
        verdict = 'WARN'
    else:
        verdict = 'FAIL'

    return {
        'present': True,
        'verdict': verdict,
        'percent': percent,
        'earned_points': earned,
        'possible_points': possible,
        'total_graded_items': len(rubric['items']),
        'total_graded_points': rubric['total_points'],
        'auto_checked_items': checkable_count,
        'failures': failures,
        'items': results,
    }
