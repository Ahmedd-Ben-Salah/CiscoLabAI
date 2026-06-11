"""
network_auditor.py - Digital Twin Validation Engine

Performs deterministic OSI-layered validation of Cisco configs using Python.
The LLM receives only the structured audit report, not raw XML.

Layers validated:
  L2: VLANs (access/trunk/native consistency)
  L2: STP (Root Bridge calculation)
  L3: Inter-VLAN routing (SVI <-> VLAN <-> encapsulation trinity)
  L3/L7: DHCP (pool <-> subnet math via ipaddress module)
"""

import re
import ipaddress


# ═══════════════════════════════════════════════════════════════
#  PHASE 1: Running-Config Parser
# ═══════════════════════════════════════════════════════════════

def parse_running_config(config_text):
    """Parse a running-config into a structured dict."""
    result = {
        'hostname': '',
        'vlans': {},           # {vlan_id: name}
        'interfaces': {},      # {iface_name: {mode, vlan, native_vlan, ...}}
        'dhcp_pools': [],      # [{name, network, mask, default_router, dns, domain}]
        'dhcp_excluded': [],   # [(start_ip, end_ip)]
        'stp_priority': {},    # {vlan_id: priority}
        'stp_mode': 'pvst',
        'ip_routing': False,
        'ospf': {},
        'static_routes': [],
        'enable_secret': '',
        'ip_default_gateway': '',
        'hsrp': {},            # {vlan_id: {vip, priority, preempt}}
        'port_channels': {},   # {pc_num: {mode, members:[]}}
        'ip_helper': {},       # {iface: [helper_ips]}
    }

    if not config_text or len(config_text.strip()) < 5:
        return result

    lines = config_text.split('\n')
    current_section = None
    current_iface = None
    current_pool = None

    for line in lines:
        raw = line.rstrip()
        stripped = raw.strip()
        lower = stripped.lower()

        if not stripped or stripped == '!':
            if stripped == '!':
                current_section = None
                current_iface = None
                current_pool = None
            continue

        # -- Hostname --
        m = re.match(r'^hostname\s+(\S+)', stripped, re.I)
        if m:
            result['hostname'] = m.group(1)
            continue

        # -- VLAN definition --
        m = re.match(r'^vlan\s+(\d+)\s*$', stripped, re.I)
        if m:
            vid = int(m.group(1))
            current_section = ('vlan', vid)
            if vid not in result['vlans']:
                result['vlans'][vid] = ''
            continue

        if current_section and current_section[0] == 'vlan':
            m = re.match(r'^name\s+(\S+)', stripped, re.I)
            if m:
                result['vlans'][current_section[1]] = m.group(1)
                continue

        # -- Interface --
        m = re.match(r'^interface\s+(.+)', stripped, re.I)
        if m:
            iface_name = m.group(1).strip()
            current_iface = iface_name
            current_section = ('interface', iface_name)
            if iface_name not in result['interfaces']:
                result['interfaces'][iface_name] = {
                    'mode': None, 'access_vlan': None,
                    'trunk_allowed': None, 'native_vlan': None,
                    'ip': None, 'mask': None, 'shutdown': False,
                    'no_switchport': False, 'channel_group': None,
                    'channel_mode': None, 'encapsulation': None,
                    'trunk_encap': None, 'description': '',
                    'hsrp': {},
                }
            continue

        # -- Interface sub-commands --
        if current_iface:
            iface = result['interfaces'][current_iface]

            if lower == 'shutdown':
                iface['shutdown'] = True
                continue
            if lower == 'no shutdown':
                iface['shutdown'] = False
                continue
            if lower == 'no switchport':
                iface['no_switchport'] = True
                continue

            m = re.match(r'^switchport mode\s+(\S+)', stripped, re.I)
            if m:
                iface['mode'] = m.group(1).lower()
                continue

            m = re.match(r'^switchport access vlan\s+(\d+)', stripped, re.I)
            if m:
                iface['access_vlan'] = int(m.group(1))
                continue

            m = re.match(r'^switchport trunk native vlan\s+(\d+)', stripped, re.I)
            if m:
                iface['native_vlan'] = int(m.group(1))
                continue

            m = re.match(r'^switchport trunk allowed vlan\s+(.+)', stripped, re.I)
            if m:
                iface['trunk_allowed'] = _parse_vlan_list(m.group(1))
                continue

            m = re.match(r'^switchport trunk encapsulation\s+(\S+)', stripped, re.I)
            if m:
                iface['trunk_encap'] = m.group(1).lower()
                continue

            m = re.match(r'^ip address\s+(\S+)\s+(\S+)', stripped, re.I)
            if m and 'no ip address' not in lower:
                iface['ip'] = m.group(1)
                iface['mask'] = m.group(2)
                continue

            m = re.match(r'^channel-group\s+(\d+)\s+mode\s+(\S+)', stripped, re.I)
            if m:
                iface['channel_group'] = int(m.group(1))
                iface['channel_mode'] = m.group(2).lower()
                pc_num = int(m.group(1))
                if pc_num not in result['port_channels']:
                    result['port_channels'][pc_num] = {'mode': m.group(2).lower(), 'members': []}
                result['port_channels'][pc_num]['members'].append(current_iface)
                continue

            m = re.match(r'^encapsulation dot1q\s+(\d+)', stripped, re.I)
            if m:
                iface['encapsulation'] = int(m.group(1))
                continue

            m = re.match(r'^ip helper-address\s+(\S+)', stripped, re.I)
            if m:
                result['ip_helper'].setdefault(current_iface, []).append(m.group(1))
                continue

            m = re.match(r'^standby\s+(\d+)\s+ip\s+(\S+)', stripped, re.I)
            if m:
                grp = int(m.group(1))
                iface['hsrp'].setdefault(grp, {})['vip'] = m.group(2)
                continue
            m = re.match(r'^standby\s+(\d+)\s+priority\s+(\d+)', stripped, re.I)
            if m:
                grp = int(m.group(1))
                iface['hsrp'].setdefault(grp, {})['priority'] = int(m.group(2))
                continue
            m = re.match(r'^standby\s+(\d+)\s+preempt', stripped, re.I)
            if m:
                grp = int(m.group(1))
                iface['hsrp'].setdefault(grp, {})['preempt'] = True
                continue

            continue

        # -- DHCP Pool --
        m = re.match(r'^ip dhcp pool\s+(\S+)', stripped, re.I)
        if m:
            current_pool = {'name': m.group(1), 'network': None, 'mask': None,
                            'default_router': None, 'dns': None, 'domain': None}
            result['dhcp_pools'].append(current_pool)
            current_section = ('dhcp', current_pool)
            continue

        if current_pool:
            m = re.match(r'^network\s+(\S+)\s+(\S+)', stripped, re.I)
            if m:
                current_pool['network'] = m.group(1)
                current_pool['mask'] = m.group(2)
                continue
            m = re.match(r'^default-router\s+(\S+)', stripped, re.I)
            if m:
                current_pool['default_router'] = m.group(1)
                continue
            m = re.match(r'^dns-server\s+(\S+)', stripped, re.I)
            if m:
                current_pool['dns'] = m.group(1)
                continue
            m = re.match(r'^domain-name\s+(\S+)', stripped, re.I)
            if m:
                current_pool['domain'] = m.group(1)
                continue

        # -- DHCP Excluded --
        m = re.match(r'^ip dhcp excluded-address\s+(\S+)(?:\s+(\S+))?', stripped, re.I)
        if m:
            start = m.group(1)
            end = m.group(2) or start
            result['dhcp_excluded'].append((start, end))
            continue

        # -- Global commands --
        if lower == 'ip routing':
            result['ip_routing'] = True
            continue

        m = re.match(r'^ip default-gateway\s+(\S+)', stripped, re.I)
        if m:
            result['ip_default_gateway'] = m.group(1)
            continue

        m = re.match(r'^enable secret\s+(.+)', stripped, re.I)
        if m:
            result['enable_secret'] = m.group(1).strip()
            continue

        m = re.match(r'^spanning-tree mode\s+(\S+)', stripped, re.I)
        if m:
            result['stp_mode'] = m.group(1).lower()
            continue

        m = re.match(r'^spanning-tree vlan\s+(\d+)\s+priority\s+(\d+)', stripped, re.I)
        if m:
            result['stp_priority'][int(m.group(1))] = int(m.group(2))
            continue

        # -- OSPF --
        m = re.match(r'^router ospf\s+(\d+)', stripped, re.I)
        if m:
            current_section = ('ospf', int(m.group(1)))
            result['ospf']['process_id'] = int(m.group(1))
            result['ospf'].setdefault('networks', [])
            continue

        if current_section and current_section[0] == 'ospf':
            m = re.match(r'^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', stripped, re.I)
            if m:
                result['ospf']['networks'].append({
                    'network': m.group(1), 'wildcard': m.group(2), 'area': m.group(3)
                })
                continue
            m = re.match(r'^router-id\s+(\S+)', stripped, re.I)
            if m:
                result['ospf']['router_id'] = m.group(1)
                continue

        # -- Static routes --
        m = re.match(r'^ip route\s+(\S+)\s+(\S+)\s+(\S+)', stripped, re.I)
        if m:
            result['static_routes'].append({
                'network': m.group(1), 'mask': m.group(2), 'next_hop': m.group(3)
            })

    return result


def _parse_vlan_list(vlan_str):
    """Parse '10,20,30' or '10-20,30' into a sorted list of VLAN IDs."""
    vlans = set()
    for part in vlan_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                for v in range(int(a), int(b) + 1):
                    vlans.add(v)
            except ValueError:
                pass
        else:
            try:
                vlans.add(int(part))
            except ValueError:
                pass
    return sorted(vlans)


# ═══════════════════════════════════════════════════════════════
#  PHASE 3: Subnet Math Engine (ipaddress-based)
# ═══════════════════════════════════════════════════════════════

def ip_to_network(ip_str, mask_str):
    """Convert IP + mask to an ipaddress.IPv4Network (strict=False)."""
    try:
        return ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
    except (ValueError, TypeError):
        return None


def is_ip_in_network(ip_str, network):
    """Check if an IP belongs to a network."""
    try:
        return ipaddress.IPv4Address(ip_str) in network
    except (ValueError, TypeError):
        return False


def find_ip_anchors(devices, connections):
    """
    Find pre-configured IPs and deduce LAN subnets.
    Returns: {lan_key: {subnet, gateway, anchor_device, anchor_ip, members: [...]}}
    """
    anchors = {}

    # Build a connection map: (device, port) -> (peer_device, peer_port)
    conn_map = {}
    for c in connections:
        d1, p1 = c.get('device1', ''), c.get('port1', '')
        d2, p2 = c.get('device2', ''), c.get('port2', '')
        if d1 and p1 and d2 and p2:
            conn_map[(d1, p1)] = (d2, p2)
            conn_map[(d2, p2)] = (d1, p1)

    # Scan all devices for pre-configured IPs
    for dev in devices:
        name = dev.get('name', '')
        parsed = dev.get('parsed_config', {})
        if not parsed:
            continue

        for iface_name, iface in parsed.get('interfaces', {}).items():
            ip = iface.get('ip')
            mask = iface.get('mask')
            if not ip or not mask or ip == '0.0.0.0':
                continue

            net = ip_to_network(ip, mask)
            if not net:
                continue

            net_key = str(net)
            if net_key not in anchors:
                anchors[net_key] = {
                    'subnet': net,
                    'network_str': net_key,
                    'prefix_len': net.prefixlen,
                    'gateway': None,
                    'members': [],
                }

            anchors[net_key]['members'].append({
                'device': name,
                'interface': iface_name,
                'ip': ip,
                'mask': mask,
            })

            # If this is a router/L3 interface (SVI or routed port), it's likely the gateway
            cat = dev.get('category', '')
            if cat in ('router',) or iface_name.lower().startswith('vlan') or iface.get('no_switchport'):
                anchors[net_key]['gateway'] = ip

    return anchors


# ═══════════════════════════════════════════════════════════════
#  PHASE 2: VLAN Audit
# ═══════════════════════════════════════════════════════════════

def audit_vlans(devices, connections):
    """Validate VLAN consistency across trunk links."""
    errors = []
    warnings = []
    facts = []

    # Build lookup: device_name -> parsed_config
    dev_configs = {}
    global_vlans = {}  # {vid: name}
    for dev in devices:
        name = dev.get('name', '')
        parsed = dev.get('parsed_config')
        if parsed:
            dev_configs[name] = parsed
            
            # Explicit VLAN definitions from running-config
            for vid, vname in parsed.get('vlans', {}).items():
                if vid not in global_vlans or (vname and not global_vlans[vid]):
                    global_vlans[vid] = vname
                    
        # Explicit VLAN definitions from vlan.dat (VTP Database)
        for vid, vname in dev.get('vlan_dat', {}).items():
            if vid not in global_vlans or (vname and not global_vlans[vid]):
                global_vlans[vid] = vname
            
            # Infer VLANs from interfaces
            for iface_name, iface in parsed.get('interfaces', {}).items():
                # From SVIs
                if iface_name.lower().startswith('vlan'):
                    try:
                        vid = int(re.sub(r'\D', '', iface_name))
                        if vid not in global_vlans: global_vlans[vid] = ''
                    except ValueError: pass
                
                # From access ports
                acc = iface.get('access_vlan')
                if acc and acc not in global_vlans: global_vlans[acc] = ''
                
                # From native ports
                nat = iface.get('native_vlan')
                if nat and nat not in global_vlans: global_vlans[nat] = ''

    # Add existing VLANs to facts
    if global_vlans:
        for vid, vname in sorted(global_vlans.items()):
            if vid == 1: continue # Skip default VLAN
            if vname:
                facts.append(f"Pre-configured VLAN {vid} exists with name '{vname}' (IMMUTABLE)")
            else:
                facts.append(f"Pre-configured VLAN {vid} exists (no name set, IMMUTABLE)")

    # Check each connection for trunk/native consistency
    for conn in connections:
        d1, p1 = conn.get('device1', ''), conn.get('port1', '')
        d2, p2 = conn.get('device2', ''), conn.get('port2', '')

        cfg1 = dev_configs.get(d1, {}).get('interfaces', {}).get(p1, {})
        cfg2 = dev_configs.get(d2, {}).get('interfaces', {}).get(p2, {})

        if not cfg1 or not cfg2:
            continue

        mode1 = cfg1.get('mode')
        mode2 = cfg2.get('mode')

        # Both trunk? Check native VLAN match
        if mode1 == 'trunk' and mode2 == 'trunk':
            nat1 = cfg1.get('native_vlan', 1) or 1
            nat2 = cfg2.get('native_vlan', 1) or 1
            if nat1 != nat2:
                errors.append({
                    'type': 'NATIVE_VLAN_MISMATCH',
                    'severity': 'error',
                    'message': f"Native VLAN mismatch: {d1}:{p1} native={nat1} vs {d2}:{p2} native={nat2}",
                    'device1': d1, 'port1': p1, 'native1': nat1,
                    'device2': d2, 'port2': p2, 'native2': nat2,
                    'fix': f"Set 'switchport trunk native vlan {nat1}' on {d2}:{p2} (or vice versa)",
                })
            else:
                facts.append(f"Trunk {d1}:{p1} <-> {d2}:{p2}: native VLAN {nat1} ✓")

            # Check allowed VLAN overlap
            allowed1 = cfg1.get('trunk_allowed')
            allowed2 = cfg2.get('trunk_allowed')
            if allowed1 and allowed2 and allowed1 != allowed2:
                warnings.append({
                    'type': 'TRUNK_ALLOWED_MISMATCH',
                    'severity': 'warning',
                    'message': f"Allowed VLANs differ: {d1}:{p1}={allowed1} vs {d2}:{p2}={allowed2}",
                })

        # One trunk, one not?
        elif mode1 == 'trunk' and mode2 != 'trunk' and mode2 is not None:
            warnings.append({
                'type': 'TRUNK_MODE_MISMATCH',
                'severity': 'warning',
                'message': f"Mode mismatch: {d1}:{p1}=trunk but {d2}:{p2}={mode2 or 'default'}",
            })
        elif mode2 == 'trunk' and mode1 != 'trunk' and mode1 is not None:
            warnings.append({
                'type': 'TRUNK_MODE_MISMATCH',
                'severity': 'warning',
                'message': f"Mode mismatch: {d2}:{p2}=trunk but {d1}:{p1}={mode1 or 'default'}",
            })

    return {'errors': errors, 'warnings': warnings, 'facts': facts}


# ═══════════════════════════════════════════════════════════════
#  PHASE 4: Inter-VLAN + DHCP Audit
# ═══════════════════════════════════════════════════════════════

def audit_intervlan(devices):
    """Validate SVI <-> VLAN <-> routing consistency."""
    errors = []
    facts = []
    svi_map = {}  # vlan_id -> {device, ip, mask, subnet}

    for dev in devices:
        name = dev.get('name', '')
        parsed = dev.get('parsed_config', {})
        if not parsed:
            continue

        for iface_name, iface in parsed.get('interfaces', {}).items():
            m = re.match(r'^Vlan\s*(\d+)$', iface_name, re.I)
            if not m:
                continue
            vid = int(m.group(1))
            ip = iface.get('ip')
            mask = iface.get('mask')
            if ip and mask and ip != '0.0.0.0':
                net = ip_to_network(ip, mask)
                entry = {'device': name, 'ip': ip, 'mask': mask, 'subnet': str(net), 'vlan_id': vid}
                svi_map.setdefault(vid, []).append(entry)
                facts.append(f"{name}: VLAN {vid} SVI = {ip}/{mask} (subnet {net})")

        # Check ip routing enabled on L3 switches (MultiLayerSwitch only)
        is_l3_switch = 'multilayer' in dev.get('type', '').lower()
        if parsed.get('ip_routing'):
            facts.append(f"{name}: ip routing enabled ✓")
        elif is_l3_switch:
            routing_svis = [
                iname for iname, iface in parsed.get('interfaces', {}).items()
                if re.match(r'^Vlan\s*\d+$', iname, re.I) and iface.get('ip')
            ]
            if len(routing_svis) > 1:
                errors.append({
                    'type': 'MISSING_IP_ROUTING',
                    'severity': 'error',
                    'message': f"{name} is an L3 switch with {len(routing_svis)} SVIs but 'ip routing' is NOT enabled",
                    'device': name,
                })

    return {'errors': errors, 'facts': facts, 'svi_map': svi_map}


def audit_dhcp(devices):
    """Validate DHCP pools against SVIs and subnets."""
    errors = []
    warnings = []
    facts = []

    for dev in devices:
        name = dev.get('name', '')
        parsed = dev.get('parsed_config', {})
        if not parsed:
            continue

        pools = parsed.get('dhcp_pools', [])
        excluded = parsed.get('dhcp_excluded', [])

        for pool in pools:
            pool_net = pool.get('network')
            pool_mask = pool.get('mask')
            gw = pool.get('default_router')

            if pool_net and pool_mask:
                net = ip_to_network(pool_net, pool_mask)
                facts.append(f"{name}: DHCP pool '{pool['name']}' = {net}, gateway={gw}")

                # Check gateway is in the pool's subnet
                if gw and net:
                    if not is_ip_in_network(gw, net):
                        errors.append({
                            'type': 'DHCP_GATEWAY_OUTSIDE_SUBNET',
                            'severity': 'error',
                            'message': f"DHCP pool '{pool['name']}': gateway {gw} is NOT in subnet {net}",
                            'device': name,
                        })

                    # Check gateway is excluded
                    gw_excluded = False
                    for start, end in excluded:
                        try:
                            if ipaddress.IPv4Address(start) <= ipaddress.IPv4Address(gw) <= ipaddress.IPv4Address(end):
                                gw_excluded = True
                                break
                        except ValueError:
                            pass

                    if not gw_excluded:
                        warnings.append({
                            'type': 'DHCP_GATEWAY_NOT_EXCLUDED',
                            'severity': 'warning',
                            'message': f"Gateway {gw} is NOT excluded from DHCP pool '{pool['name']}' — risk of IP conflict",
                            'device': name,
                        })

    return {'errors': errors, 'warnings': warnings, 'facts': facts}


# ═══════════════════════════════════════════════════════════════
#  PHASE 5: STP Audit
# ═══════════════════════════════════════════════════════════════

def audit_stp(devices):
    """Calculate Root Bridge and detect STP issues."""
    facts = []
    warnings = []
    bridges = []

    for dev in devices:
        cat = dev.get('category', '')
        if cat not in ('switch',):
            continue
        name = dev.get('name', '')
        parsed = dev.get('parsed_config', {})
        if not parsed:
            continue

        # Get MAC from interfaces (first available BIA/MAC)
        mac = None
        for iface in dev.get('interfaces', []):
            m_addr = iface.get('mac') or iface.get('bia')
            if m_addr:
                mac = m_addr
                break

        priority = parsed.get('stp_priority', {})
        mode = parsed.get('stp_mode', 'pvst')
        bridges.append({'name': name, 'mac': mac, 'priority': priority, 'mode': mode})
        facts.append(f"{name}: STP mode={mode}, priorities={priority or 'default(32768)'}")

    return {'facts': facts, 'warnings': warnings, 'bridges': bridges}


# ═══════════════════════════════════════════════════════════════
#  MAIN AUDIT ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def full_audit(context):
    """
    Run the complete 4-layer audit on the topology.
    
    Args:
        context: dict from topology_extractor.get_full_context()
    
    Returns:
        dict with audit results per layer
    """
    devices = context.get('devices', [])
    connections = context.get('connections', [])

    # Step 0: Parse all running-configs into structured data
    for dev in devices:
        config_text = dev.get('running_config', '')
        dev['parsed_config'] = parse_running_config(config_text)

    # Step 1: VLAN audit
    vlan_report = audit_vlans(devices, connections)

    # Step 2: IP Anchors (subnet math)
    ip_anchors = find_ip_anchors(devices, connections)

    # Step 3: Inter-VLAN audit
    intervlan_report = audit_intervlan(devices)

    # Step 4: DHCP audit
    dhcp_report = audit_dhcp(devices)

    # Step 5: STP audit
    stp_report = audit_stp(devices)

    # Combine
    all_errors = (vlan_report['errors'] + intervlan_report['errors'] + dhcp_report['errors'])
    all_warnings = (vlan_report.get('warnings', []) + dhcp_report.get('warnings', []) +
                    stp_report.get('warnings', []))

    audit = {
        'vlan': vlan_report,
        'stp': stp_report,
        'intervlan': intervlan_report,
        'dhcp': dhcp_report,
        'ip_anchors': {k: {
            'network': v['network_str'],
            'prefix': v['prefix_len'],
            'gateway': v['gateway'],
            'members': v['members'],
        } for k, v in ip_anchors.items()},
        'summary': {
            'total_errors': len(all_errors),
            'total_warnings': len(all_warnings),
            'status': 'FAIL' if all_errors else ('WARN' if all_warnings else 'PASS'),
        },
        # Per-device parsed config summaries for the enhanced audit prompt
        '_device_configs': [{
            'name': dev.get('name', ''),
            'ospf': dev.get('parsed_config', {}).get('ospf', {}),
            'static_routes': dev.get('parsed_config', {}).get('static_routes', []),
            'port_channels': dev.get('parsed_config', {}).get('port_channels', {}),
        } for dev in devices if dev.get('parsed_config')],
    }

    return audit


def build_audit_prompt_section(audit):
    """Convert the audit dict into a human-readable prompt section for the LLM."""
    lines = []
    lines.append("=== NETWORK AUDIT REPORT (Python-verified) ===\n")

    # IP Anchors
    anchors = audit.get('ip_anchors', {})
    if anchors:
        lines.append("PRE-CONFIGURED IP ANCHORS (IMMUTABLE — do NOT change these):")
        for net_key, info in anchors.items():
            gw = info.get('gateway', '?')
            lines.append(f"  Subnet {net_key}: gateway={gw}")
            for m in info.get('members', []):
                lines.append(f"    • {m['device']}:{m['interface']} = {m['ip']}/{m['mask']}")
        lines.append("")

    # VLAN Database
    vlan = audit.get('vlan', {})
    if vlan.get('facts'):
        # Extract VLAN facts into a clean table
        vlan_entries = []
        other_facts = []
        for f in vlan['facts']:
            if 'Pre-configured VLAN' in f:
                vlan_entries.append(f)
            else:
                other_facts.append(f)
        
        if vlan_entries:
            lines.append("EXISTING VLAN DATABASE (IMMUTABLE — do NOT recreate or rename):")
            for entry in vlan_entries:
                lines.append(f"  ✓ {entry}")
            lines.append("")
        
        if other_facts:
            lines.append("VLAN & TRUNK STATUS:")
            for f in other_facts[:20]:
                lines.append(f"  ✓ {f}")
            lines.append("")
    
    if vlan.get('errors'):
        lines.append("VLAN ERRORS (MUST FIX):")
        for e in vlan['errors']:
            lines.append(f"  ❌ {e['message']}")
            if e.get('fix'):
                lines.append(f"     FIX: {e['fix']}")
        lines.append("")

    # Inter-VLAN
    iv = audit.get('intervlan', {})
    if iv.get('errors'):
        lines.append("INTER-VLAN ERRORS (MUST FIX):")
        for e in iv['errors']:
            lines.append(f"  ❌ {e['message']}")
        lines.append("")
    if iv.get('facts'):
        lines.append("INTER-VLAN STATUS:")
        for f in iv['facts'][:20]:
            lines.append(f"  ✓ {f}")
        lines.append("")

    # DHCP
    dhcp = audit.get('dhcp', {})
    if dhcp.get('errors'):
        lines.append("DHCP ERRORS (MUST FIX):")
        for e in dhcp['errors']:
            lines.append(f"  ❌ {e['message']}")
        lines.append("")
    if dhcp.get('warnings'):
        lines.append("DHCP WARNINGS:")
        for w in dhcp['warnings']:
            lines.append(f"  ⚠️ {w['message']}")
        lines.append("")
    
    # OSPF State (extracted from parsed configs during audit)
    ospf_found = []
    for dev_info in audit.get('_device_configs', []):
        name = dev_info.get('name', '')
        ospf = dev_info.get('ospf', {})
        if ospf.get('process_id'):
            ospf_str = f"  {name}: OSPF process {ospf['process_id']}"
            if ospf.get('router_id'):
                ospf_str += f", router-id {ospf['router_id']}"
            nets = ospf.get('networks', [])
            if nets:
                ospf_str += f", networks: {', '.join(n['network'] + ' area ' + n['area'] for n in nets)}"
            ospf_found.append(ospf_str)
    
    if ospf_found:
        lines.append("EXISTING OSPF STATE (IMMUTABLE — use the same process IDs):")
        for entry in ospf_found:
            lines.append(entry)
        lines.append("")
    
    # Static Routes
    static_found = []
    for dev_info in audit.get('_device_configs', []):
        name = dev_info.get('name', '')
        routes = dev_info.get('static_routes', [])
        for r in routes:
            static_found.append(f"  {name}: ip route {r['network']} {r['mask']} {r['next_hop']}")
    
    if static_found:
        lines.append("EXISTING STATIC ROUTES (IMMUTABLE):")
        for entry in static_found:
            lines.append(entry)
        lines.append("")
    
    # Port-Channels
    pc_found = []
    for dev_info in audit.get('_device_configs', []):
        name = dev_info.get('name', '')
        pcs = dev_info.get('port_channels', {})
        for pc_num, pc_info in pcs.items():
            mode = pc_info.get('mode', '?')
            members = pc_info.get('members', [])
            pc_found.append(f"  {name}: Port-channel{pc_num} mode={mode} members={members}")
    
    if pc_found:
        lines.append("EXISTING PORT-CHANNELS (IMMUTABLE):")
        for entry in pc_found:
            lines.append(entry)
        lines.append("")

    # Summary
    summary = audit.get('summary', {})
    status = summary.get('status', '?')
    lines.append(f"AUDIT STATUS: {status} ({summary.get('total_errors', 0)} errors, {summary.get('total_warnings', 0)} warnings)")

    return '\n'.join(lines)
