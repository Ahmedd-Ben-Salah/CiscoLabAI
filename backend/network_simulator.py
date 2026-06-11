"""
network_simulator.py - Control-plane reachability oracle (answer-key-independent)

Builds a deterministic model of the network from the extracted topology + parsed
running-configs, then proves end-to-end reachability WITHOUT needing an answer key
or a running Packet Tracer. This is the foundation oracle: if PC-A can reach PC-B
according to the routing/forwarding model, that objective is satisfied — regardless
of whether the .pka embeds a grading rubric.

Scope of this first cut:
  - L3 forwarding: connected routes, static routes, and an OSPF "cloud"
    approximation (single-area full-adjacency, typical for CCNA labs).
  - Hop-by-hop forward AND return path checking (asymmetric routing is caught).
  - L2-within-subnet is ASSUMED to work but flagged 'uncertain' when VLANs/trunks
    are present on the path (detailed L2/VLAN correctness lives in invariants.py).

Consumes the dict from topology_extractor.get_full_context().
"""

import ipaddress
from network_auditor import parse_running_config, ip_to_network


# ═══════════════════════════════════════════════════════════════
#  Model construction
# ═══════════════════════════════════════════════════════════════

def _net(ip, mask):
    """ip+mask -> IPv4Network (host bits cleared), or None."""
    if not ip or not mask:
        return None
    return ip_to_network(ip, mask)


def build_model(context):
    """
    Build a routing/forwarding model from the topology context.

    Returns a dict:
      {
        'routers':   {name: {'iface_ips': [(ifname, ip, net)],
                             'connected': [net], 'static': [(net, next_hop)],
                             'ospf': bool, 'ospf_networks': [net]}},
        'endpoints': {name: {'ip', 'mask', 'gw', 'net'}},      # PCs/servers
        'l3_ifaces': [(device, ifname, ip, net)],              # every routed IP
        'gw_owner':  {ip_str: (device, ifname)},               # who owns an IP
        'vlans_present': bool,
        'parsed':    {name: parsed_config},
      }
    """
    model = {
        'routers': {}, 'endpoints': {}, 'l3_ifaces': [],
        'gw_owner': {}, 'vlans_present': False, 'parsed': {},
    }

    for dev in context.get('devices', []):
        name = dev.get('name', '')
        cat = dev.get('category', 'generic')

        # ── PCs / servers: single NIC endpoint from extracted interface data ──
        # Always register the endpoint (even if unconfigured) so the oracle can
        # report exactly what's missing instead of silently dropping it.
        if cat in ('pc', 'server'):
            ip = mask = gw = ipv6 = None
            for iface in dev.get('interfaces', []):
                ip = ip or iface.get('ip')
                mask = mask or iface.get('mask')
                gw = gw or iface.get('gateway')
                ipv6 = ipv6 or iface.get('ipv6')
            gw = gw or dev.get('gateway')
            net = _net(ip, mask) if (ip and ip != '0.0.0.0' and mask) else None
            model['endpoints'][name] = {
                'kind': cat, 'ip': ip, 'mask': mask, 'gw': gw,
                'ipv6': ipv6, 'net': net,
            }
            if net:
                model['l3_ifaces'].append((name, 'NIC', ip, net))
                model['gw_owner'][ip] = (name, 'NIC')
            continue

        # ── Routers / switches: authoritative running-config ──
        parsed = parse_running_config(dev.get('running_config', ''))
        model['parsed'][name] = parsed
        if parsed.get('vlans'):
            model['vlans_present'] = True

        is_router = cat == 'router'
        is_l3_switch = parsed.get('ip_routing', False)  # MLS with `ip routing`

        connected, iface_ips = [], []
        for ifname, iface in parsed.get('interfaces', {}).items():
            ip, mask = iface.get('ip'), iface.get('mask')
            if iface.get('shutdown'):
                continue
            if not ip or not mask or ip == '0.0.0.0':
                continue
            net = _net(ip, mask)
            if not net:
                continue
            # An L3 interface routes if it's on a router, or an SVI/no-switchport
            # port on an L3-capable switch.
            routes = is_router or is_l3_switch
            iface_ips.append((ifname, ip, net))
            model['l3_ifaces'].append((name, ifname, ip, net))
            model['gw_owner'][ip] = (name, ifname)
            if routes:
                connected.append(net)

        if is_router or is_l3_switch:
            ospf = parsed.get('ospf') or {}
            statics = []
            for r in parsed.get('static_routes', []):
                snet = _net(r.get('network'), r.get('mask'))
                if snet:
                    statics.append((snet, r.get('next_hop')))
            # OSPF cloud: connected nets covered by a `network ... area` statement.
            ospf_nets = []
            if ospf.get('process_id') is not None:
                for n in connected:
                    if _covered_by_ospf(n, ospf.get('networks', [])):
                        ospf_nets.append(n)
            model['routers'][name] = {
                'iface_ips': iface_ips,
                'connected': connected,
                'static': statics,
                'ospf': ospf.get('process_id') is not None,
                'ospf_networks': ospf_nets,
            }

    return model


def _covered_by_ospf(net, ospf_networks):
    """True if a connected net falls inside any OSPF `network <addr> <wildcard>`."""
    for stmt in ospf_networks:
        try:
            base = ipaddress.IPv4Address(stmt['network'])
            wild = ipaddress.IPv4Address(stmt['wildcard'])
            # wildcard -> prefix length
            inv = int(wild)
            prefix = 32 - bin(inv).count('1')
            stmt_net = ipaddress.IPv4Network(f"{stmt['network']}/{prefix}", strict=False)
            if net.network_address in stmt_net or net.subnet_of(stmt_net):
                return True
            # network statement targeting this exact interface address
            if base in net:
                return True
        except (ValueError, KeyError):
            continue
    return False


# ═══════════════════════════════════════════════════════════════
#  Forwarding / reachability
# ═══════════════════════════════════════════════════════════════

def _router_owning(model, ip_str):
    """Return the router name whose connected subnet contains ip_str (or owns it)."""
    if not ip_str:
        return None
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return None
    # Exact interface ownership first
    owner = model['gw_owner'].get(ip_str)
    if owner and owner[0] in model['routers']:
        return owner[0]
    # Else any router with a connected subnet containing the IP
    for rname, r in model['routers'].items():
        for net in r['connected']:
            if addr in net:
                return rname
    return None


def _ospf_cloud_subnets(model):
    """All subnets advertised into OSPF by any OSPF-speaking router."""
    subnets = []
    if not any(r['ospf'] for r in model['routers'].values()):
        return subnets
    for r in model['routers'].values():
        if r['ospf']:
            subnets.extend(r['ospf_networks'])
    return subnets


def _route_lookup(model, router_name, dst_addr):
    """
    One forwarding decision on a router. Returns:
      ('connected', net)         dst is on a directly connected subnet
      ('static', next_hop_ip)    forward to next hop
      ('ospf', net)              reachable via OSPF cloud
      (None, reason)             no route
    """
    r = model['routers'].get(router_name)
    if not r:
        return (None, f"{router_name} is not a router")

    # Longest-prefix-ish: prefer connected, then static, then ospf.
    best = None
    for net in r['connected']:
        if dst_addr in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    if best is not None:
        return ('connected', best)

    best_static = None
    for net, nh in r['static']:
        if dst_addr in net and (best_static is None or net.prefixlen > best_static[0].prefixlen):
            best_static = (net, nh)
    if best_static is not None:
        return ('static', best_static[1])

    if r['ospf']:
        for net in _ospf_cloud_subnets(model):
            if dst_addr in net:
                return ('ospf', net)

    return (None, f"no route to {dst_addr} on {router_name}")


def _forward(model, start_router, dst_ip, max_hops=16):
    """
    Simulate forwarding from start_router toward dst_ip.
    Returns (delivered: bool, path: [router names], reason: str).
    """
    try:
        dst = ipaddress.IPv4Address(dst_ip)
    except ValueError:
        return (False, [], f"invalid destination {dst_ip}")

    path, current, seen = [], start_router, set()
    for _ in range(max_hops):
        if current is None:
            return (False, path, "next hop not owned by any router")
        if current in seen:
            return (False, path, f"routing loop at {current}")
        seen.add(current)
        path.append(current)

        kind, info = _route_lookup(model, current, dst)
        if kind in ('connected', 'ospf'):
            return (True, path, "delivered")
        if kind == 'static':
            current = _router_owning(model, info)  # follow next hop
            continue
        return (False, path, info)  # info is the reason
    return (False, path, "max hops exceeded")


def can_reach(model, src_name, dst_name):
    """
    Can endpoint src reach endpoint dst (both PCs/servers)?
    Checks forward AND return path. Returns a structured result.
    """
    src = model['endpoints'].get(src_name)
    dst = model['endpoints'].get(dst_name)
    res = {'src': src_name, 'dst': dst_name, 'reachable': False,
           'uncertain': False, 'reason': '', 'path': []}

    def _incomplete(ep, who):
        if not ep:
            return f"{who} is not a known endpoint"
        if not ep.get('ip') or ep.get('ip') == '0.0.0.0':
            return f"{who} has no IP address"
        if not ep.get('mask'):
            return f"{who} has an IP but no subnet mask"
        return None

    bad = _incomplete(src, src_name) or _incomplete(dst, dst_name)
    if bad:
        res['reason'] = bad
        return res

    dst_addr = ipaddress.IPv4Address(dst['ip'])

    # Same subnet → L2 path assumed (flagged uncertain when VLANs in play).
    if dst_addr in src['net']:
        res['reachable'] = True
        res['reason'] = "same subnet (L2 assumed)"
        res['uncertain'] = model['vlans_present']
        return res

    # Different subnet → src needs a gateway owned by a reachable router.
    if not src.get('gw'):
        res['reason'] = f"{src_name} has no default gateway (needs one to leave its subnet)"
        return res
    first_hop = _router_owning(model, src['gw'])
    if not first_hop:
        res['reason'] = f"{src_name}'s gateway {src['gw']} is not a live router interface"
        return res

    fwd_ok, fwd_path, fwd_reason = _forward(model, first_hop, dst['ip'])
    if not fwd_ok:
        res['path'] = fwd_path
        res['reason'] = f"forward path failed: {fwd_reason}"
        return res

    # Return path: dst's gateway back to src.
    if not dst.get('gw'):
        res['path'] = fwd_path
        res['reason'] = f"return path failed: {dst_name} has no default gateway"
        return res
    ret_hop = _router_owning(model, dst['gw'])
    if not ret_hop:
        res['reason'] = f"return path failed: {dst_name}'s gateway {dst['gw']} is not a live router interface"
        return res
    ret_ok, ret_path, ret_reason = _forward(model, ret_hop, src['ip'])
    if not ret_ok:
        res['path'] = fwd_path
        res['reason'] = f"return path failed: {ret_reason}"
        return res

    res['reachable'] = True
    res['path'] = fwd_path
    res['reason'] = "delivered (forward + return verified)"
    res['uncertain'] = model['vlans_present']
    return res


def simulate(context):
    """
    Top-level entry: build the model and test reachability across all endpoint
    pairs plus each host -> its own gateway.

    Returns:
      {'endpoints': [...names...],
       'pairs': [reachability result, ...],
       'gateway_checks': [...],
       'summary': {'reachable': n, 'unreachable': n, 'uncertain': n}}
    """
    model = build_model(context)
    eps = sorted(model['endpoints'].keys())

    # Per-endpoint config completeness (the most common lab gap: PCs with no IP).
    endpoint_status = []
    for name in eps:
        ep = model['endpoints'][name]
        missing = []
        if not ep.get('ip') or ep.get('ip') == '0.0.0.0':
            missing.append('ip')
        if not ep.get('mask'):
            missing.append('mask')
        if not ep.get('gw'):
            missing.append('gateway')
        endpoint_status.append({
            'device': name, 'kind': ep.get('kind'),
            'ip': ep.get('ip'), 'mask': ep.get('mask'), 'gw': ep.get('gw'),
            'complete': not missing, 'missing': missing,
        })

    pairs, reach, unreach, uncert = [], 0, 0, 0
    for i, a in enumerate(eps):
        for b in eps[i + 1:]:
            r = can_reach(model, a, b)
            pairs.append(r)
            if r['reachable']:
                reach += 1
                if r['uncertain']:
                    uncert += 1
            else:
                unreach += 1

    gw_checks = []
    for name, ep in model['endpoints'].items():
        gw = ep.get('gw')
        if not gw:
            gw_checks.append({'device': name, 'ok': False,
                              'reason': 'no default gateway configured'})
            continue
        owner = _router_owning(model, gw)
        same_subnet = False
        if ep.get('net'):
            try:
                same_subnet = ipaddress.IPv4Address(gw) in ep['net']
            except ValueError:
                pass
        gw_checks.append({
            'device': name, 'gateway': gw, 'ok': bool(owner) and same_subnet,
            'reason': 'ok' if (owner and same_subnet)
                      else ('gateway not in host subnet' if not same_subnet
                            else 'gateway is not a live router interface'),
        })

    incomplete = sum(1 for e in endpoint_status if not e['complete'])
    return {
        'endpoints': eps,
        'endpoint_status': endpoint_status,
        'pairs': pairs,
        'gateway_checks': gw_checks,
        'summary': {'reachable': reach, 'unreachable': unreach,
                    'uncertain': uncert, 'incomplete_endpoints': incomplete},
    }
