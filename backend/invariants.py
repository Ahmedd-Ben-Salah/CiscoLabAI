"""
invariants.py - Answer-key-independent protocol consistency checks

These are "compiler-style" checks: they catch configurations that are wrong on
their own terms — independent of any instructor answer key — by validating the
intrinsic rules every Cisco network must obey. This is what hardens the
"L2 assumed" guesses from network_simulator.py into real pass/fail signal, and
gives the tool real coverage of advanced topics (VLANs/trunks, EtherChannel,
STP, HSRP, DHCP, OSPF adjacency).

Each check yields findings shaped as:
    {severity: 'error'|'warning'|'info', category, devices: [...],
     component, message, fix_hint}

Consumes topology_extractor.get_full_context() output.
"""

import ipaddress
import re
from network_auditor import parse_running_config, ip_to_network


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

_IF_ABBR = [
    (r'^te(?:n|ngig\w*)?', 'TenGigabitEthernet'),
    (r'^gig?\w*', 'GigabitEthernet'),
    (r'^fa\w*', 'FastEthernet'),
    (r'^eth?\w*', 'Ethernet'),
    (r'^se\w*', 'Serial'),
    (r'^po\w*', 'Port-channel'),
    (r'^vl\w*', 'Vlan'),
    (r'^lo\w*', 'Loopback'),
]


def normalize_iface(name):
    """Canonicalize an interface name so config + cabling names compare equal.
    'Gi0/1' -> 'GigabitEthernet0/1', 'Fa0/1' -> 'FastEthernet0/1'."""
    if not name:
        return ''
    name = name.strip()
    m = re.match(r'^([A-Za-z\-]+)\s*(.*)$', name)
    if not m:
        return name
    head, tail = m.group(1).lower(), m.group(2).strip()
    for pat, full in _IF_ABBR:
        if re.match(pat, head):
            return f"{full}{tail}"
    return name


def _finding(severity, category, devices, component, message, fix_hint=''):
    return {'severity': severity, 'category': category,
            'devices': devices if isinstance(devices, list) else [devices],
            'component': component, 'message': message, 'fix_hint': fix_hint}


def _vlan_id_from_svi(ifname):
    m = re.match(r'(?:vlan|Vlan)\s*0*(\d+)', ifname, re.I)
    return int(m.group(1)) if m else None


def build_link_map(connections):
    """(device, normalized_iface) -> (peer_device, peer_normalized_iface)."""
    link_map = {}
    for c in connections:
        d1, p1 = c.get('device1'), normalize_iface(c.get('port1', ''))
        d2, p2 = c.get('device2'), normalize_iface(c.get('port2', ''))
        if d1 and p1 and d2 and p2:
            link_map[(d1, p1)] = (d2, p2)
            link_map[(d2, p2)] = (d1, p1)
    return link_map


def build_devices(context):
    """{name: {'cat', 'parsed', 'ifaces': {norm_if: iface}, 'vlans': {vid:name}}}."""
    devices = {}
    for d in context.get('devices', []):
        name = d.get('name')
        cat = d.get('category', 'generic')
        if cat in ('pc', 'server', 'phone', 'printer', 'cloud', 'generic'):
            # end devices: keep IP for duplicate-IP checks
            devices[name] = {'cat': cat, 'parsed': None, 'ifaces': {},
                             'endpoint': d.get('interfaces', []), 'vlans': {}}
            continue
        parsed = parse_running_config(d.get('running_config', ''))
        ifaces = {normalize_iface(k): v for k, v in parsed.get('interfaces', {}).items()}
        # merge vlan.dat into the VLAN database
        vlans = dict(parsed.get('vlans', {}))
        for vid, vname in (d.get('vlan_dat') or {}).items():
            vlans.setdefault(vid, vname)
        devices[name] = {'cat': cat, 'parsed': parsed, 'ifaces': ifaces, 'vlans': vlans}
    return devices


# ─────────────────────────────────────────────────────────────────
#  Checks
# ─────────────────────────────────────────────────────────────────

def check_duplicate_ips(devices):
    findings = []
    seen = {}  # ip -> (device, iface)
    for name, dev in devices.items():
        if dev['parsed']:
            for ifn, iface in dev['ifaces'].items():
                ip = iface.get('ip')
                if ip and ip != '0.0.0.0':
                    where = (name, ifn)
                    if ip in seen and seen[ip][0] != name:
                        findings.append(_finding(
                            'error', 'ip', [name, seen[ip][0]], ip,
                            f"Duplicate IP {ip} on {name}:{ifn} and {seen[ip][0]}:{seen[ip][1]}",
                            "Assign distinct IPs; only one device may own an address."))
                    seen.setdefault(ip, where)
        else:
            for iface in dev.get('endpoint', []):
                ip = iface.get('ip')
                if ip and ip != '0.0.0.0':
                    if ip in seen and seen[ip][0] != name:
                        findings.append(_finding(
                            'error', 'ip', [name, seen[ip][0]], ip,
                            f"Duplicate IP {ip} on {name} and {seen[ip][0]}",
                            "Assign distinct IPs to each host."))
                    seen.setdefault(ip, (name, 'NIC'))
    return findings


def check_trunks(devices, link_map):
    """Native-VLAN, mode, allowed-VLAN, and encapsulation consistency across links."""
    findings = []
    checked = set()
    for (dev, ifn), (peer, pifn) in link_map.items():
        if (peer, pifn, dev, ifn) in checked:
            continue
        checked.add((dev, ifn, peer, pifn))
        da, db = devices.get(dev), devices.get(peer)
        if not da or not db or not da['parsed'] or not db['parsed']:
            continue
        ia, ib = da['ifaces'].get(ifn), db['ifaces'].get(pifn)
        if not ia or not ib:
            continue
        mode_a, mode_b = ia.get('mode'), ib.get('mode')
        a_trunk = mode_a == 'trunk'
        b_trunk = mode_b == 'trunk'

        # Mode mismatch: one trunk, the other explicitly access
        if a_trunk and mode_b == 'access':
            findings.append(_finding('error', 'trunk', [dev, peer], f"{dev}:{ifn}",
                f"Link {dev}:{ifn}(trunk) ↔ {peer}:{pifn}(access) — mode mismatch",
                "Set both ends to trunk, or both to access."))
        if b_trunk and mode_a == 'access':
            findings.append(_finding('error', 'trunk', [dev, peer], f"{peer}:{pifn}",
                f"Link {peer}:{pifn}(trunk) ↔ {dev}:{ifn}(access) — mode mismatch",
                "Set both ends to trunk, or both to access."))

        if a_trunk and b_trunk:
            # Native VLAN must match (defaults to 1)
            na = ia.get('native_vlan') or 1
            nb = ib.get('native_vlan') or 1
            if na != nb:
                findings.append(_finding('error', 'trunk', [dev, peer], 'native vlan',
                    f"Native VLAN mismatch on trunk {dev}:{ifn}(vlan {na}) ↔ {peer}:{pifn}(vlan {nb})",
                    "Set the same native VLAN on both trunk ends."))
            # Allowed VLAN set should match
            aa, ab = ia.get('trunk_allowed'), ib.get('trunk_allowed')
            if aa is not None and ab is not None and set(aa) != set(ab):
                findings.append(_finding('warning', 'trunk', [dev, peer], 'allowed vlan',
                    f"Allowed-VLAN set differs on trunk {dev}:{ifn} vs {peer}:{pifn}",
                    "Make 'switchport trunk allowed vlan' identical on both ends."))
            # 3560/3650 MLS need dot1q encapsulation set before trunk mode
            for d_, i_, iface_ in ((dev, ifn, ia), (peer, pifn, ib)):
                model = ''  # encapsulation only required on certain MLS; warn if missing on a routing switch
                if devices[d_]['parsed'].get('ip_routing') and not iface_.get('trunk_encap'):
                    findings.append(_finding('warning', 'trunk', [d_], f"{d_}:{i_}",
                        f"Trunk {d_}:{i_} on L3 switch has no 'switchport trunk encapsulation dot1q'",
                        "On 3560/3650, set 'switchport trunk encapsulation dot1q' before 'switchport mode trunk'."))
    return findings


def check_access_vlans(devices):
    """An access port's VLAN must exist in that switch's VLAN database."""
    findings = []
    for name, dev in devices.items():
        if not dev['parsed']:
            continue
        for ifn, iface in dev['ifaces'].items():
            av = iface.get('access_vlan')
            if av and av not in dev['vlans'] and av != 1:
                findings.append(_finding('warning', 'vlan', [name], f"{name}:{ifn}",
                    f"Access port {name}:{ifn} uses VLAN {av}, which is not defined on {name}",
                    f"Create 'vlan {av}' on {name} (or via VTP)."))
    return findings


def _etherchannel_compat(mode_a, mode_b):
    """Are two channel-group modes compatible? Returns (ok, reason)."""
    lacp = {'active', 'passive'}
    pagp = {'desirable', 'auto'}
    if mode_a == 'on' and mode_b == 'on':
        return True, ''
    if mode_a == 'on' or mode_b == 'on':
        return False, "'on' must pair with 'on' (no negotiation)"
    if mode_a in lacp and mode_b in lacp:
        if mode_a == 'passive' and mode_b == 'passive':
            return False, "LACP passive/passive never forms — make one side active"
        return True, ''
    if mode_a in pagp and mode_b in pagp:
        if mode_a == 'auto' and mode_b == 'auto':
            return False, "PAgP auto/auto never forms — make one side desirable"
        return True, ''
    return False, f"protocol mismatch ({mode_a} vs {mode_b}) — both must be LACP or both PAgP"


def check_etherchannel(devices, link_map):
    findings = []
    reported = set()
    for name, dev in devices.items():
        if not dev['parsed']:
            continue
        for pc_num, pc in dev['parsed'].get('port_channels', {}).items():
            members = [normalize_iface(m) for m in pc.get('members', [])]
            mode_a = pc.get('mode')
            # find the peer device/port-channel via the members' physical links
            peer_devs, peer_modes = set(), set()
            for m in members:
                peer = link_map.get((name, m))
                if not peer:
                    continue
                pdev, pifn = peer
                peer_devs.add(pdev)
                pd = devices.get(pdev)
                if pd and pd['parsed']:
                    pif = pd['ifaces'].get(pifn, {})
                    if pif.get('channel_mode'):
                        peer_modes.add(pif.get('channel_mode'))
            key = tuple(sorted([name] + list(peer_devs))) + (pc_num,)
            if key in reported:
                continue
            reported.add(key)
            if len(peer_devs) > 1:
                findings.append(_finding('error', 'etherchannel', [name] + list(peer_devs),
                    f"Port-channel {pc_num}",
                    f"{name} Po{pc_num} bundles links going to multiple devices {sorted(peer_devs)}",
                    "All EtherChannel members must connect to the SAME neighbor."))
                continue
            for mb in peer_modes:
                ok, reason = _etherchannel_compat(mode_a, mb)
                if not ok:
                    findings.append(_finding('error', 'etherchannel',
                        [name] + list(peer_devs), f"Port-channel {pc_num}",
                        f"EtherChannel mode mismatch {name}({mode_a}) ↔ {sorted(peer_devs)}({mb}): {reason}",
                        "Use compatible channel-group modes on both ends."))
    return findings


def check_inter_vlan_routing(devices):
    """SVIs only route when 'ip routing' is enabled on the (multilayer) switch."""
    findings = []
    for name, dev in devices.items():
        if not dev['parsed'] or dev['cat'] != 'switch':
            continue
        svis = [ifn for ifn, i in dev['ifaces'].items()
                if _vlan_id_from_svi(ifn) and i.get('ip')]
        # more than one IP'd SVI implies inter-VLAN routing intent
        if len(svis) >= 2 and not dev['parsed'].get('ip_routing'):
            findings.append(_finding('error', 'routing', [name], 'ip routing',
                f"{name} has SVIs {svis} with IPs but 'ip routing' is not enabled — inter-VLAN routing won't work",
                f"Add 'ip routing' on {name}."))
    return findings


def check_hsrp(devices):
    """HSRP peers must share group + virtual IP, and the VIP must sit in subnet."""
    findings = []
    # group HSRP by VLAN id
    by_vlan = {}  # vid -> [(device, ifn, grp, info, subnet)]
    for name, dev in devices.items():
        if not dev['parsed']:
            continue
        for ifn, iface in dev['ifaces'].items():
            vid = _vlan_id_from_svi(ifn)
            for grp, info in (iface.get('hsrp') or {}).items():
                subnet = None
                if iface.get('ip') and iface.get('mask'):
                    subnet = ip_to_network(iface['ip'], iface['mask'])
                by_vlan.setdefault(vid, []).append((name, ifn, grp, info, subnet))
    for vid, entries in by_vlan.items():
        vips = {e[3].get('vip') for e in entries if e[3].get('vip')}
        groups = {e[2] for e in entries}
        devs = [e[0] for e in entries]
        if len(vips) > 1:
            findings.append(_finding('error', 'hsrp', devs, f"VLAN {vid}",
                f"HSRP virtual IP differs between peers on VLAN {vid}: {vips}",
                "Both HSRP peers must use the SAME virtual IP."))
        if len(groups) > 1:
            findings.append(_finding('error', 'hsrp', devs, f"VLAN {vid}",
                f"HSRP group number differs between peers on VLAN {vid}: {groups}",
                "Use the same standby group number on both peers."))
        # VIP must be inside the SVI subnet
        for name, ifn, grp, info, subnet in entries:
            vip = info.get('vip')
            if vip and subnet and ipaddress.ip_address(vip) not in subnet:
                findings.append(_finding('error', 'hsrp', [name], f"{name}:{ifn}",
                    f"HSRP virtual IP {vip} is not inside the SVI subnet {subnet}",
                    "Pick a virtual IP within the VLAN's subnet."))
        # priorities should differ so there's a deterministic active
        prios = [e[3].get('priority', 100) for e in entries]
        if len(entries) >= 2 and len(set(prios)) == 1:
            findings.append(_finding('info', 'hsrp', devs, f"VLAN {vid}",
                f"HSRP peers on VLAN {vid} share priority {prios[0]} — active is decided by IP, not design",
                "Give the intended active peer a higher 'standby priority' and 'preempt'."))
    return findings


def check_dhcp(devices):
    """Pool network must match a real gateway subnet; gateway should be excluded."""
    findings = []
    # collect all routed subnets (for matching pools to a real segment)
    subnets = []
    for name, dev in devices.items():
        if not dev['parsed']:
            continue
        for ifn, iface in dev['ifaces'].items():
            if iface.get('ip') and iface.get('mask'):
                net = ip_to_network(iface['ip'], iface['mask'])
                if net:
                    subnets.append(net)
    for name, dev in devices.items():
        if not dev['parsed']:
            continue
        excluded = dev['parsed'].get('dhcp_excluded', [])
        for pool in dev['parsed'].get('dhcp_pools', []):
            net = ip_to_network(pool.get('network'), pool.get('mask')) if pool.get('network') else None
            if not net:
                continue
            if not any(net.network_address == s.network_address and net.prefixlen == s.prefixlen for s in subnets):
                findings.append(_finding('warning', 'dhcp', [name], f"pool {pool.get('name')}",
                    f"DHCP pool '{pool.get('name')}' network {net} matches no router/SVI subnet",
                    "Pool network/mask should equal the gateway interface's subnet."))
            gw = pool.get('default_router')
            if gw:
                try:
                    if ipaddress.ip_address(gw) not in net:
                        findings.append(_finding('warning', 'dhcp', [name], f"pool {pool.get('name')}",
                            f"DHCP default-router {gw} is not inside pool subnet {net}",
                            "default-router must be the gateway within the pool subnet."))
                    else:
                        # gateway should be excluded from the lease range
                        if not _ip_excluded(gw, excluded):
                            findings.append(_finding('info', 'dhcp', [name], f"pool {pool.get('name')}",
                                f"Gateway {gw} is not in any 'ip dhcp excluded-address' range",
                                "Exclude the gateway (and other static IPs) from the DHCP pool."))
                except ValueError:
                    pass
    return findings


def _ip_excluded(ip, excluded):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for start, end in excluded:
        try:
            if ipaddress.ip_address(start) <= a <= ipaddress.ip_address(end):
                return True
        except ValueError:
            continue
    return False


def check_ospf_adjacency(devices, link_map):
    """Across a router-to-router link, both OSPF interfaces must be in same area;
    and an interface with an IP that OSPF should cover but doesn't is flagged."""
    findings = []

    def area_for(dev, iface):
        """Area an interface is advertised into, or None."""
        ospf = devices[dev]['parsed'].get('ospf') or {}
        ip, mask = iface.get('ip'), iface.get('mask')
        if not ip or not ospf.get('networks'):
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for stmt in ospf['networks']:
            try:
                base = ipaddress.ip_address(stmt['network'])
                wild = int(ipaddress.ip_address(stmt['wildcard']))
                prefix = 32 - bin(wild).count('1')
                snet = ipaddress.ip_network(f"{stmt['network']}/{prefix}", strict=False)
                if addr in snet:
                    return str(stmt['area'])
            except (ValueError, KeyError):
                continue
        return None

    checked = set()
    for (dev, ifn), (peer, pifn) in link_map.items():
        if (peer, pifn, dev, ifn) in checked:
            continue
        checked.add((dev, ifn, peer, pifn))
        da, db = devices.get(dev), devices.get(peer)
        if not da or not db or not da['parsed'] or not db['parsed']:
            continue
        oa = da['parsed'].get('ospf') or {}
        ob = db['parsed'].get('ospf') or {}
        if oa.get('process_id') is None or ob.get('process_id') is None:
            continue
        ia, ib = da['ifaces'].get(ifn), db['ifaces'].get(pifn)
        if not ia or not ib or not ia.get('ip') or not ib.get('ip'):
            continue
        area_a, area_b = area_for(dev, ia), area_for(peer, ib)
        if area_a and area_b and area_a != area_b:
            findings.append(_finding('error', 'ospf', [dev, peer], 'area',
                f"OSPF area mismatch across {dev}:{ifn}(area {area_a}) ↔ {peer}:{pifn}(area {area_b})",
                "Both ends of an OSPF adjacency must be in the same area."))
        if (area_a is None) != (area_b is None):
            missing = dev if area_a is None else peer
            mif = ifn if area_a is None else pifn
            findings.append(_finding('warning', 'ospf', [missing], f"{missing}:{mif}",
                f"{missing}:{mif} is not advertised into OSPF but its neighbor is — adjacency won't form",
                f"Add a 'network' statement covering {mif} on {missing}."))
    return findings


# ─────────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────────

def full_invariants(context):
    """Run every consistency check and return {findings, summary}."""
    devices = build_devices(context)
    link_map = build_link_map(context.get('connections', []))

    findings = []
    findings += check_duplicate_ips(devices)
    findings += check_trunks(devices, link_map)
    findings += check_access_vlans(devices)
    findings += check_etherchannel(devices, link_map)
    findings += check_inter_vlan_routing(devices)
    findings += check_hsrp(devices)
    findings += check_dhcp(devices)
    findings += check_ospf_adjacency(devices, link_map)

    summary = {
        'errors': sum(1 for f in findings if f['severity'] == 'error'),
        'warnings': sum(1 for f in findings if f['severity'] == 'warning'),
        'info': sum(1 for f in findings if f['severity'] == 'info'),
    }
    return {'findings': findings, 'summary': summary}
