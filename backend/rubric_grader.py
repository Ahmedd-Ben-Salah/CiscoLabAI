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

Only attributes we can resolve unambiguously from the running-config / VLAN table
are auto-checked: hostname, per-interface IPv4/IPv6 + mask, VLAN id->name, OSPF
router-id + network statements, static routes, switch default-gateway, and router
DHCP pools (network/mask). Everything else (passive-interface enumerations, RIP
auto-summary, reference-bandwidth defaults, server-hosted DHCP pools, ...) is
reported `checkable=False` so we never emit a false negative for something we
simply didn't model.
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

# Rubric "sections" (path[2]) and attribute names this module knows how to read
# back out of a device's running-config / VLAN table. Anything outside these is
# parsed into the rubric but reported checkable=False (never a false negative).
SEC_HOSTNAME = 'Host Name'
SEC_PORTS = 'Ports'
SEC_VLANS = 'VLANS'
SEC_OSPF = 'OSPF'
SEC_ROUTES = 'Routes'
SEC_DEFAULT_GW = 'Default Gateway'
SEC_DHCP = 'DHCP Server List'

ATTR_IP = 'IP Address'
ATTR_MASK = 'Subnet Mask'


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
                # path = ['Network', device, section, ... , attribute]
                device = new_path[1] if len(new_path) > 1 else ''
                section = new_path[2] if len(new_path) > 2 else ''
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
                    'section': section,
                    'interface': interface,
                    'attribute': attribute,
                    'path': new_path,
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


def _prefix_to_mask(prefix):
    try:
        return str(ipaddress.IPv4Network('0.0.0.0/%s' % int(prefix)).netmask)
    except (ValueError, ipaddress.NetmaskValueError):
        return None


def _device_index(device):
    """Parse everything we can grade out of one device.

    Returns sets/dicts keyed for membership checks:
      hostname, ipv4, masks, ipv6, has_rc,
      vlans  {id:int -> name},
      ospf   {pid:str -> {'router_id', 'networks'(set 'net wild area')}},
      static (set 'net mask nexthop'),
      default_gw,
      dhcp   {pool:str -> {'network', 'mask'}}
    """
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

    vlans = {}
    for k, v in (device.get('vlan_dat') or {}).items():
        try:
            vlans[int(k)] = v
        except (TypeError, ValueError):
            pass

    rc = device.get('running_config', '') or ''
    ospf, static, dhcp = {}, set(), {}
    default_gw = host = None
    cur_ospf = cur_pool = cur_vlan = None

    for raw in rc.splitlines():
        s = raw.strip()
        if not s:
            continue
        indented = raw[:1] in (' ', '\t')
        if not indented:                       # a global command closes any block
            cur_ospf = cur_pool = cur_vlan = None

        m = re.match(r'hostname\s+(\S+)', s)
        if m:
            host = m.group(1)
            continue
        m = re.match(r'ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', s)
        if m:
            ipv4.add(m.group(1))
            masks.add(m.group(2))
            continue
        m = re.match(r'ipv6 address (\S+)', s, re.I)
        if m:
            v6 = _norm_v6(m.group(1))
            if v6:
                ipv6.add(v6)
            continue
        m = re.match(r'router ospf (\d+)', s)
        if m:
            cur_ospf = m.group(1)
            ospf.setdefault(cur_ospf, {'router_id': None, 'networks': set()})
            continue
        m = re.match(r'ip route (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\S+)', s)
        if m:
            static.add('%s %s %s' % (m.group(1), m.group(2), m.group(3)))
            continue
        m = re.match(r'ip default-gateway (\S+)', s)
        if m:
            default_gw = m.group(1)
            continue
        m = re.match(r'ip dhcp pool (\S+)', s)
        if m:
            cur_pool = m.group(1)
            dhcp.setdefault(cur_pool, {'network': None, 'mask': None})
            continue
        m = re.match(r'vlan (\d+)', s)
        if m:
            cur_vlan = int(m.group(1))
            vlans.setdefault(cur_vlan, None)
            continue

        if cur_ospf:
            m = re.match(r'router-id (\S+)', s)
            if m:
                ospf[cur_ospf]['router_id'] = m.group(1)
                continue
            m = re.match(r'network (\S+) (\S+) area (\S+)', s)
            if m:
                ospf[cur_ospf]['networks'].add('%s %s %s' % m.groups())
                continue
        if cur_pool:
            m = re.match(r'network (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', s)
            if m:
                dhcp[cur_pool]['network'] = m.group(1)
                dhcp[cur_pool]['mask'] = m.group(2)
                continue
        if cur_vlan is not None:
            m = re.match(r'name (\S+)', s)
            if m:
                vlans[cur_vlan] = m.group(1)
                continue

    return {
        'hostname': host, 'ipv4': ipv4, 'masks': masks, 'ipv6': ipv6,
        'has_rc': bool(rc.strip()),
        'vlans': vlans, 'ospf': ospf, 'static': static,
        'default_gw': default_gw, 'dhcp': dhcp,
    }


def _seg_in_path(path, pattern):
    r"""Scan a path list for the first element matching `pattern` and return its
    first capture group. e.g. pattern r'VLAN (\d+)' pulls the VLAN id."""
    for el in path:
        m = re.search(pattern, el)
        if m:
            return m.group(1)
    return None


def _resolve_actual(item, idx):
    """Resolve a rubric item against a device index. Returns (actual, ok, checkable).

    checkable=False means "we don't model this attribute" — it is excluded from the
    score so we never penalise a value we simply didn't read."""
    section = item['section']
    attr = item['attribute']
    expected = item['expected']
    path = item['path']

    # ── Host name ──────────────────────────────────────────────────────────────
    if section == SEC_HOSTNAME:
        actual = idx.get('hostname')
        return actual, (actual == expected), True

    # ── Interface IPv4 / IPv6 / mask (device-level address membership) ─────────
    if section == SEC_PORTS and attr == ATTR_MASK:
        ok = expected in idx['masks']
        return (expected if ok else (', '.join(sorted(idx['masks'])) or None)), ok, True
    if section == SEC_PORTS and attr == ATTR_IP:
        if ':' in expected:
            want = _norm_v6(expected)
            ok = want is not None and want in idx['ipv6']
            return (expected if ok else (', '.join(sorted(idx['ipv6'])) or None)), ok, True
        ok = expected in idx['ipv4']
        return (expected if ok else (', '.join(sorted(idx['ipv4'])) or None)), ok, True

    # ── VLANs: VLAN <id> -> name ───────────────────────────────────────────────
    if section == SEC_VLANS and attr == 'VLAN Name':
        if not idx['vlans']:                      # no VLAN data extracted -> can't tell
            return None, False, False
        vid = _seg_in_path(path, r'VLAN (\d+)')
        actual = idx['vlans'].get(int(vid)) if vid is not None else None
        return actual, (actual == expected), True

    # ── OSPF: router-id and network statements (per process) ───────────────────
    if section == SEC_OSPF and idx['has_rc']:
        pid = _seg_in_path(path, r'Process ID (\d+)')
        proc = idx['ospf'].get(pid, {}) if pid else {}
        if attr == 'Router ID':
            actual = proc.get('router_id')
            return actual, (actual == expected), True
        if 'Networks' in path:                    # expected = 'net wild area'
            nets = proc.get('networks', set())
            ok = expected in nets
            return (expected if ok else (', '.join(sorted(nets)) or None)), ok, True
        # Auto Cost (reference-bandwidth default 100) and Passive Interface are not
        # reliably present in running-config -> leave them unchecked.
        return None, False, False

    # ── Static routes: 'net-prefixlen-nexthop-metric' ──────────────────────────
    if section == SEC_ROUTES and idx['has_rc'] and 'Static Routes' in path:
        parts = expected.split('-')
        if len(parts) >= 3:
            net, prefix, nexthop = parts[0], parts[1], parts[2]
            mask = _prefix_to_mask(prefix)
            if mask is not None:
                key = '%s %s %s' % (net, mask, nexthop)
                ok = key in idx['static']
                return (key if ok else (', '.join(sorted(idx['static'])) or None)), ok, True
        return None, False, False

    # ── Switch default gateway ─────────────────────────────────────────────────
    if section == SEC_DEFAULT_GW and idx['has_rc']:
        actual = idx['default_gw']
        return actual, (actual == expected), True

    # ── Router DHCP pools (server-hosted pools aren't in running-config) ───────
    if section == SEC_DHCP and idx['has_rc']:
        pool = _seg_in_path(path, r'Pool (\S+)')
        data = idx['dhcp'].get(pool, {}) if pool else {}
        if attr == 'Name':
            ok = pool in idx['dhcp']
            return (pool if ok else None), ok, True
        if attr == 'Network Address':
            actual = data.get('network')
            return actual, (actual == expected), True
        if attr == 'Subnet mask':
            actual = data.get('mask')
            return actual, (actual == expected), True
        # Start IP / Pool IPs / Max User are PT server-DHCP fields -> unchecked.
        return None, False, False

    return None, False, False


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
            'section': it['section'],
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
