"""
topology_extractor.py - Extract topology, devices, connections, and instructions from PKA XML

Parses the XML structure of a decoded Packet Tracer file to extract:
- All devices (routers, switches, PCs, servers) with their interfaces and configs
- All connections (cables between devices)
- Lab activity instructions (HTML)
- Device configurations (running-config, startup-config)
"""

import xml.etree.ElementTree as ET
import re
import html


def _sanitize_xml(xml_string):
    """Remove illegal XML 1.0 characters that cause parser failures."""
    _illegal_xml_chars_RE = re.compile(
        '[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF]'
    )
    return _illegal_xml_chars_RE.sub('', xml_string)


def parse_xml(xml_string):
    """Parse XML string into an ElementTree root element."""
    xml_string = _sanitize_xml(xml_string)
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        # Try cleaning up common XML issues
        xml_string = xml_string.replace('&', '&amp;').replace('&amp;amp;', '&amp;')
        root = ET.fromstring(xml_string)
    return root


def extract_devices(root):
    """
    Extract all devices from the XML tree.
    
    Returns:
        list of dict: Each device with name, type, model, interfaces, config, position
    """
    devices = []
    seen_names = set()
    
    # Look for devices in various possible XML paths
    device_elements = root.findall('.//DEVICE')
    if not device_elements:
        device_elements = root.findall('.//device')
    
    for dev_elem in device_elements:
        device = {}
        
        # Extract from ENGINE section
        engine = dev_elem.find('ENGINE')
        if engine is None: 
            engine = dev_elem.find('engine')
        if engine is None: 
            engine = dev_elem
            
        # Device name
        name_elem = engine.find('NAME')
        if name_elem is None:
            name_elem = engine.find('name')
            
        if name_elem is not None:
            device['name'] = (name_elem.text or '').strip()
        else:
            device['name'] = f"Device_{len(devices)}"
            
        if device['name'] in seen_names:
            continue
            
        seen_names.add(device['name'])
        
        # Device type and model
        type_elem = engine.find('TYPE')
        if type_elem is None:
            type_elem = engine.find('type')
            
        if type_elem is not None:
            device['type'] = (type_elem.text or '').strip()
            device['model'] = type_elem.get('model', '') or type_elem.get('customModel', '')
        else:
            device['type'] = 'Unknown'
            device['model'] = ''
        
        # Power state
        power_elem = engine.find('POWER')
        if power_elem is None:
            power_elem = engine.find('power')
        device['powered'] = (power_elem.text or '').strip().lower() == 'true' if power_elem is not None else True
        
        # Running config
        config_elem = engine.find('.//RUNNINGCONFIG')
        if config_elem is None:
            config_elem = engine.find('.//runningconfig')
            
        if config_elem is not None:
            lines = config_elem.findall('LINE')
            if lines:
                config_text = '\n'.join((l.text or '') for l in lines)
                device['running_config'] = config_text
            else:
                device['running_config'] = (config_elem.text or '').strip()
        else:
            device['running_config'] = ''
        
        # Startup config  
        startup_elem = engine.find('.//STARTUPCONFIG')
        if startup_elem is None:
            startup_elem = engine.find('.//startupconfig')
            
        if startup_elem is not None:
            lines = startup_elem.findall('LINE')
            if lines:
                device['startup_config'] = '\n'.join((l.text or '') for l in lines)
            else:
                device['startup_config'] = (startup_elem.text or '').strip()
        else:
            device['startup_config'] = ''
        
        # Extract interfaces
        device['interfaces'] = _extract_interfaces(engine)
        
        # Extract modules
        device['modules'] = _extract_modules(engine)
        
        # Physical position
        phys = dev_elem.find('.//PHYSICALWORKSPACE')
        if phys is not None:
            dev_phys = phys.find('.//DEVICE') or phys.find('DEVICE')
            if dev_phys is not None:
                device['x'] = float(dev_phys.get('x', 0))
                device['y'] = float(dev_phys.get('y', 0))
            else:
                device['x'] = 0
                device['y'] = 0
        else:
            device['x'] = 0
            device['y'] = 0
            
        # Extract vlan.dat (VLAN database)
        device['vlan_dat'] = {}
        vlan_dat_elem = engine.find('.//FILE_CONTENT[@class="CVlanDatFileContent"]')
        if vlan_dat_elem is not None:
            vlans_elem = vlan_dat_elem.find('VLANS')
            if vlans_elem is not None:
                for v in vlans_elem.findall('VLAN'):
                    vid_str = v.get('number')
                    vname = v.get('name')
                    if vid_str and vname:
                        try:
                            device['vlan_dat'][int(vid_str)] = vname
                        except ValueError:
                            pass
        
        # Determine device category for icons
        device['category'] = _categorize_device(device['type'], device['model'])
        
        devices.append(device)
    
    return devices


def _extract_interfaces(engine_elem):
    """Extract interface information from a device engine element."""
    interfaces = []
    
    # For routers/switches: find MODULE > SLOT > MODULE > PORT structure
    # For PCs: PORT is directly under MODULE > SLOT > MODULE
    for port in engine_elem.findall('.//PORT'):
        iface = {}
        
        # Port type gives us the interface category
        type_elem = port.find('TYPE') or port.find('type')
        port_type = (type_elem.text or '').strip() if type_elem is not None else ''
        
        # Skip non-network ports (like Bluetooth, USB)
        if port_type in ('eBluetooth', 'eUSB'):
            continue
        
        iface['port_type'] = port_type
        
        # NAME is often absent for PCs. For Routers, PORT doesn't have NAME either.
        # The interface name is typically reconstructed from the port type.
        # NOTE: a leaf ElementTree element is falsy, so `a or b` silently drops a
        # populated leaf — must compare against None explicitly.
        name_elem = port.find('NAME')
        if name_elem is None:
            name_elem = port.find('name')
        iface['name'] = (name_elem.text or '').strip() if name_elem is not None else ''

        # IP address — direct child of PORT
        ip_elem = port.find('IP')
        if ip_elem is not None and ip_elem.text:
            iface['ip'] = ip_elem.text.strip()

        # Subnet mask
        mask_elem = port.find('SUBNET')
        if mask_elem is None:
            mask_elem = port.find('MASK')
        if mask_elem is not None and mask_elem.text:
            iface['mask'] = mask_elem.text.strip()
        
        # IPv6
        ipv6_addrs = port.find('IPV6_ADDRESSES')
        if ipv6_addrs is not None:
            for ipv6 in ipv6_addrs.findall('IPV6_ADDRESS'):
                addr_el = ipv6.find('ADDRESS')
                prefix_el = ipv6.find('PREFIX')
                if addr_el is not None and addr_el.text:
                    iface['ipv6'] = addr_el.text.strip()
                    if prefix_el is not None and prefix_el.text:
                        iface['ipv6'] += '/' + prefix_el.text.strip()
        
        # Gateway
        gw_elem = port.find('PORT_GATEWAY')
        if gw_elem is not None and gw_elem.text:
            iface['gateway'] = gw_elem.text.strip()
        
        interfaces.append(iface)
    
    # Also check for the global GATEWAY tag (PCs have it outside PORT)
    gw = engine_elem.find('GATEWAY')
    if gw is not None and gw.text and gw.text.strip():
        # Attach it to the first interface
        if interfaces and 'gateway' not in interfaces[0]:
            interfaces[0]['gateway'] = gw.text.strip()
    
    return interfaces


def _extract_modules(engine_elem):
    """Extract module information from a device."""
    modules = []
    
    for mod in engine_elem.findall('.//MODULE') + engine_elem.findall('.//module'):
        module = {}
        type_elem = mod.find('TYPE') or mod.find('type')
        module['type'] = (type_elem.text or '').strip() if type_elem is not None else ''
        
        # Slot info
        slot_elem = mod.find('SLOT') or mod.find('slot')
        module['slot'] = (slot_elem.text or '').strip() if slot_elem is not None else ''
        
        modules.append(module)
    
    return modules


def _categorize_device(device_type, model):
    """Categorize a device for icon display purposes."""
    type_lower = (device_type or '').lower()
    model_lower = (model or '').lower()
    
    if 'router' in type_lower or any(m in model_lower for m in ['1841', '2811', '2901', '4321', 'isr']):
        return 'router'
    elif 'switch' in type_lower or any(m in model_lower for m in ['2960', '3560', '3650', '3850']):
        return 'switch'
    elif 'pc' in type_lower or 'workstation' in type_lower or 'laptop' in type_lower:
        return 'pc'
    elif 'server' in type_lower:
        return 'server'
    elif 'phone' in type_lower:
        return 'phone'
    elif 'printer' in type_lower:
        return 'printer'
    elif 'cloud' in type_lower:
        return 'cloud'
    elif 'wireless' in type_lower or 'ap' in type_lower:
        return 'wireless'
    else:
        return 'generic'


def extract_connections(root):
    """
    Extract all cable connections from the XML tree.
    Supports both legacy CONNECTION/ENDPOINT format and PT8 LINK/CABLE/FROM/TO format.
    
    Returns:
        list of dict: Each connection with endpoints and cable type
    """
    connections = []
    
    # --- PT8 format: LINK > CABLE with FROM/TO save-ref-ids ---
    # First build a save-ref-id -> device name lookup table
    ref_to_name = {}
    for device in root.findall('.//DEVICE'):
        engine = device.find('ENGINE') or device.find('.//ENGINE')
        if engine is not None:
            name_el = engine.find('NAME')
            save_ref = engine.find('SAVE_REF_ID')
            if name_el is not None and name_el.text and save_ref is not None and save_ref.text:
                ref_to_name[save_ref.text] = name_el.text
    
    seen_connections = set()  # Deduplicate (PT8 stores logical + physical duplicates)
    
    for link in root.findall('.//LINK'):
        cable = link.find('CABLE')
        if cable is None:
            continue
        
        from_ref_el = cable.find('FROM')
        to_ref_el = cable.find('TO')
        ports = cable.findall('PORT')
        
        if from_ref_el is None or to_ref_el is None or len(ports) < 2:
            continue
        
        from_ref = from_ref_el.text or ''
        to_ref = to_ref_el.text or ''
        from_port = ports[0].text or ''
        to_port = ports[1].text or ''
        
        from_name = ref_to_name.get(from_ref, from_ref)
        to_name = ref_to_name.get(to_ref, to_ref)
        
        # Cable type
        cable_type_el = cable.find('TYPE')
        cable_type = (cable_type_el.text or 'Copper').strip() if cable_type_el is not None else 'Copper'
        
        # Deduplicate: use sorted device pair + ports as unique key
        conn_key = tuple(sorted([(from_name, from_port), (to_name, to_port)]))
        if conn_key in seen_connections:
            continue
        seen_connections.add(conn_key)
        
        connection = {
            'device1': from_name,
            'port1': from_port,
            'device2': to_name,
            'port2': to_port,
            'cable_type': cable_type,
        }
        connections.append(connection)
    
    # --- Legacy format: CONNECTION/ENDPOINT (fallback for older PT files) ---
    if not connections:
        for conn in root.findall('.//CONNECTION') + root.findall('.//connection'):
            connection = {}
            
            type_elem = conn.find('TYPE') or conn.find('type')
            connection['cable_type'] = (type_elem.text or '').strip() if type_elem is not None else 'Copper Straight-Through'
            
            ep1 = conn.find('.//ENDPOINT1') or conn.find('.//endpoint1')
            if ep1 is None:
                endpoints = conn.findall('.//ENDPOINT') or conn.findall('.//endpoint')
                if len(endpoints) >= 2:
                    ep1 = endpoints[0]
                    ep2 = endpoints[1]
                else:
                    continue
            else:
                ep2 = conn.find('.//ENDPOINT2') or conn.find('.//endpoint2')
            
            if ep1 is not None:
                dev1 = ep1.find('DEVICE') or ep1.find('device')
                port1 = ep1.find('PORT') or ep1.find('port')
                connection['device1'] = (dev1.text or '').strip() if dev1 is not None else ep1.get('device', '')
                connection['port1'] = (port1.text or '').strip() if port1 is not None else ep1.get('port', '')
            
            if ep2 is not None:
                dev2 = ep2.find('DEVICE') or ep2.find('device')
                port2 = ep2.find('PORT') or ep2.find('port')
                connection['device2'] = (dev2.text or '').strip() if dev2 is not None else ep2.get('device', '')
                connection['port2'] = (port2.text or '').strip() if port2 is not None else ep2.get('port', '')
            
            connections.append(connection)
    
    return connections


def extract_instructions(root):
    """
    Extract lab activity instructions from the XML tree.
    
    Returns:
        str: The instructions as HTML or plain text
    """
    instructions = ""
    
    # Try various known paths for instructions
    paths = [
        './/ACTIVITY/INSTRUCTIONS',
        './/ACTIVITY/ACTIVITYTEXT',
        './/ACTIVITY',
        './/activity/instructions',
        './/ACTIVITYTEXT',
        './/INSTRUCTIONS',
        './/DESCRIPTION',
    ]
    
    for path in paths:
        elem = root.find(path)
        if elem is not None:
            # Get all text content including nested elements
            text = _get_all_text(elem)
            if text and len(text.strip()) > 20:  # Meaningful content
                instructions = text.strip()
                break
    
    # If still empty, try to find any large text block that looks like instructions
    if not instructions:
        for elem in root.iter():
            if elem.text and len(elem.text.strip()) > 200:
                if any(keyword in elem.text.lower() for keyword in 
                       ['partie', 'part', 'step', 'étape', 'configure', 'configurer',
                        'instruction', 'objectif', 'objective', 'topology']):
                    instructions = elem.text.strip()
                    break
    
    return instructions


def _get_all_text(element):
    """Recursively get all text content from an XML element."""
    parts = []
    if element.text:
        parts.append(element.text)
    for child in element:
        parts.append(_get_all_text(child))
        if child.tail:
            parts.append(child.tail)
    return ' '.join(parts)


def extract_version(root):
    """Extract the Packet Tracer version from the XML."""
    version_elem = root.find('.//VERSION') or root.find('.//version')
    if version_elem is not None:
        return (version_elem.text or '').strip()
    return 'Unknown'


def extract_workspace_notes(root):
    """
    Extract any floating text notes from the Packet Tracer workspace.
    These often contain IP addresses or instructions not in the devices.
    """
    notes = []
    # Search all tags that end with TEXT since different PT versions use TEXT, ACTIVITYTEXT, etc. but avoid huge configs
    for elem in root.iter():
        tag = elem.tag.upper()
        if 'TEXT' in tag and elem.text:
            text = elem.text.strip()
            # Ignore very long instruction blocks or empty ones
            if text and len(text) < 500:
                # Also ignore some generic PT system texts
                if text not in ['Locking / Starting', 'False', 'True'] and not text.startswith('save-ref-id:'):
                    notes.append(text)
    
    # Deduplicate notes
    unique_notes = []
    for note in notes:
        if note not in unique_notes:
            unique_notes.append(note)
            
    return unique_notes


def get_full_context(xml_string):
    """
    Extract everything needed for AI processing.
    
    Returns:
        dict: Complete topology context including devices, connections, 
              instructions, and version info
    """
    root = parse_xml(xml_string)
    
    devices = extract_devices(root)
    connections = extract_connections(root)
    instructions = extract_instructions(root)
    version = extract_version(root)
    workspace_notes = extract_workspace_notes(root)
    
    # Build a human-readable topology summary for the AI
    topology_summary = _build_topology_summary(devices, connections, workspace_notes)
    
    return {
        'version': version,
        'devices': devices,
        'connections': connections,
        'instructions': instructions,
        'workspace_notes': workspace_notes,
        'topology_summary': topology_summary,
        'device_count': len(devices),
        'connection_count': len(connections),
    }


def _build_topology_summary(devices, connections, workspace_notes=None):
    """Build a human-readable text summary of the network topology.
    
    The key insight: PORT elements in PKA XML often lack NAME tags,
    so we reconstruct interface info primarily from CONNECTION data
    (which reliably contains correct IOS-style interface names like
    'GigabitEthernet1/0/1', 'FastEthernet0/1', etc.)
    """
    lines = []
    lines.append("=== NETWORK TOPOLOGY ===\n")
    
    if workspace_notes:
        lines.append("WORKSPACE NOTES (Floating Text on Screen — may contain IP addresses or instructions):")
        for note in workspace_notes:
            lines.append(f"  - {note}")
        lines.append("\n")
    
    # ── Build a per-device port map from connections ──
    # This is the PRIMARY source of truth for interface names
    device_ports = {}  # device_name -> list of {port, connected_to, connected_port, cable_type}
    for conn in connections:
        d1, p1 = conn.get('device1', ''), conn.get('port1', '')
        d2, p2 = conn.get('device2', ''), conn.get('port2', '')
        cable = conn.get('cable_type', 'Cable')
        
        if d1 and p1:
            device_ports.setdefault(d1, []).append({
                'port': p1, 'connected_to': d2, 'connected_port': p2, 'cable': cable
            })
        if d2 and p2:
            device_ports.setdefault(d2, []).append({
                'port': p2, 'connected_to': d1, 'connected_port': p1, 'cable': cable
            })
    
    # ── Device Inventory ──
    lines.append("DEVICES:")
    for dev in devices:
        name = dev['name']
        dtype = dev.get('type', 'Unknown')
        model = dev.get('model', '')
        cat = dev.get('category', 'generic')
        
        lines.append(f"\n  ■ {name} (type: {dtype}, model: {model}, category: {cat})")
        
        # Show connected interfaces from connection data (reliable names)
        ports = device_ports.get(name, [])
        if ports:
            lines.append(f"    Connected Interfaces:")
            for p in ports:
                lines.append(f"      • {p['port']}  →  {p['connected_to']}:{p['connected_port']}  [{p['cable']}]")
        
        # Show IPs from interface data  
        if dev.get('interfaces'):
            ips_found = []
            for iface in dev['interfaces']:
                ip = iface.get('ip', '')
                if ip and ip != 'none' and ip != '0.0.0.0':
                    mask = iface.get('mask', '')
                    gw = iface.get('gateway', '')
                    ipv6 = iface.get('ipv6', '')
                    entry = f"IP: {ip}"
                    if mask:
                        entry += f" / {mask}"
                    if gw:
                        entry += f" (Gateway: {gw})"
                    if ipv6:
                        entry += f" | IPv6: {ipv6}"
                    ips_found.append(entry)
            if ips_found:
                lines.append(f"    IP Addresses Configured:")
                for ip_entry in ips_found:
                    lines.append(f"      • {ip_entry}")
    
    # ── Connection Wiring Diagram ──
    lines.append("\n\nCOMPLETE WIRING DIAGRAM (exact port-to-port connections):")
    lines.append("  Format: DeviceA:PortA  <──cable──>  DeviceB:PortB")
    lines.append("")
    for conn in connections:
        d1 = conn.get('device1', '?')
        p1 = conn.get('port1', '?')
        d2 = conn.get('device2', '?')
        p2 = conn.get('port2', '?')
        cable = conn.get('cable_type', 'cable')
        lines.append(f"  {d1}:{p1}  <──{cable}──>  {d2}:{p2}")
    
    # ── Device State (Pseudo Running-Config Format) ──
    lines.append("\n\n" + "=" * 60)
    lines.append("EXISTING DEVICE CONFIGURATIONS")
    lines.append("(Presented as Cisco IOS 'show running-config' format)")
    lines.append("CRITICAL: DO NOT modify any IP address, VLAN, or protocol")
    lines.append("that is already configured below. Only ADD what is MISSING.")
    lines.append("=" * 60)
    
    for dev in devices:
        name = dev['name']
        cat = dev.get('category', 'generic')
        model = dev.get('model', '')
        
        if cat in ('pc', 'server'):
            # PC/Server: show IP config as structured block
            lines.append(f"\n{'─' * 50}")
            lines.append(f"CURRENT DEVICE STATE ({name} — {cat.upper()}):")
            has_ip = False
            for iface in dev.get('interfaces', []):
                ip = iface.get('ip', '')
                if ip and ip != '0.0.0.0':
                    has_ip = True
                    mask = iface.get('mask', '')
                    gw = iface.get('gateway', '')
                    ipv6 = iface.get('ipv6', '')
                    lines.append(f"  IP Address:      {ip}")
                    lines.append(f"  Subnet Mask:     {mask or '(not set)'}")
                    lines.append(f"  Default Gateway: {gw or '(not set)'}")
                    if ipv6:
                        lines.append(f"  IPv6 Address:    {ipv6}")
            if not has_ip:
                lines.append("  IP Address:      (not configured)")
                lines.append("  Subnet Mask:     (not configured)")
                lines.append("  Default Gateway: (not configured)")
                lines.append("  >>> THIS DEVICE NEEDS IP CONFIGURATION <<<")
        else:
            # Router/Switch: show in IOS running-config format
            config_text = dev.get('running_config', '')
            vlan_dat = dev.get('vlan_dat', {})
            
            lines.append(f"\n{'─' * 50}")
            lines.append(f"CURRENT DEVICE STATE ({name} — {model or cat}):")
            lines.append(f"! Output of 'show running-config'")
            
            if config_text and len(config_text.strip()) > 10:
                # Insert VLAN database entries that are NOT already in the running-config
                # (VTP stores VLANs in vlan.dat, not in running-config)
                extra_vlans = []
                for vid, vname in sorted(vlan_dat.items()):
                    if vid >= 1002:
                        continue  # Skip FDDI/TokenRing defaults
                    if vid == 1:
                        continue  # Skip default VLAN
                    # Check if this VLAN is already defined in running-config
                    if not re.search(rf'^vlan\s+{vid}\s*$', config_text, re.MULTILINE):
                        extra_vlans.append((vid, vname))
                
                if extra_vlans:
                    lines.append("!")
                    lines.append("! --- VLANs from VLAN Database (vlan.dat) ---")
                    for vid, vname in extra_vlans:
                        lines.append(f"vlan {vid}")
                        if vname:
                            lines.append(f" name {vname}")
                
                # Output the actual running-config
                for cfg_line in config_text.split('\n'):
                    lines.append(cfg_line.rstrip())
            else:
                lines.append("! (no running-config found — device may be unconfigured)")
                
                # Still show vlan.dat if available
                if vlan_dat:
                    lines.append("!")
                    lines.append("! --- VLANs from VLAN Database (vlan.dat) ---")
                    for vid, vname in sorted(vlan_dat.items()):
                        if vid >= 1002 or vid == 1:
                            continue
                        lines.append(f"vlan {vid}")
                        if vname:
                            lines.append(f" name {vname}")
    
    return '\n'.join(lines)

