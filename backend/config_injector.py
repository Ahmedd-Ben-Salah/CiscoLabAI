"""
config_injector.py - Inject AI-generated configurations back into the PKA XML

Handles:
- Setting running-config and startup-config on routers/switches
- Configuring PC/Server IP settings
- Applying the AI solution to the XML tree
"""

import xml.etree.ElementTree as ET
import re
import copy


def _expand_interface_range(range_spec):
    """
    Expand 'interface range' specification into individual interface names.
    
    Examples:
        "GigabitEthernet1/0/1-2" -> ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"]
        "Gi1/0/1-2, Gi1/0/3-4" -> ["GigabitEthernet1/0/1", ..., "GigabitEthernet1/0/4"]
        "FastEthernet0/1-3" -> ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"]
    """
    # Normalize abbreviations
    range_spec = re.sub(r'\bGi\b', 'GigabitEthernet', range_spec)
    range_spec = re.sub(r'\bFa\b', 'FastEthernet', range_spec)
    
    result = []
    # Split by comma for multiple ranges
    parts = [p.strip() for p in range_spec.split(',')]
    
    for part in parts:
        # Match pattern like "GigabitEthernet1/0/1-4" or "GigabitEthernet1/0/1 - 4"
        match = re.match(r'^([A-Za-z]+[\d/]+/)(\d+)\s*-\s*(\d+)$', part)
        if match:
            prefix = match.group(1)
            start = int(match.group(2))
            end = int(match.group(3))
            for n in range(start, end + 1):
                result.append(f"{prefix}{n}")
        else:
            # Maybe just a single interface, add as-is
            if re.match(r'^[A-Za-z]', part):
                result.append(part)
    
    return result if result else None


def find_device_element(root, device_name):
    """
    Find a device element in the XML tree by name.
    
    Args:
        root: XML root element
        device_name: Name of the device to find
        
    Returns:
        Element or None: The DEVICE element if found
    """
    for device in root.findall('.//DEVICE'):
        engine = device.find('.//ENGINE') or device
        name_elem = engine.find('.//NAME') or engine.find('.//name')
        if name_elem is not None and (name_elem.text or '').strip() == device_name:
            return device
    
    # Case-insensitive fallback
    for device in root.findall('.//DEVICE'):
        engine = device.find('.//ENGINE') or device
        name_elem = engine.find('.//NAME') or engine.find('.//name')
        if name_elem is not None and (name_elem.text or '').strip().lower() == device_name.lower():
            return device
    
    return None


def validate_commands(commands, parsed_config, audit_report=None):
    """
    Python guardrail: Filter dangerous or hallucinated AI commands.
    
    Protects:
    - Immutable VLANs (don't rename existing VLANs)
    - Immutable IPs (don't overwrite anchored IPs)
    - Immutable OSPF processes (don't delete existing routing)
    - Blocks destructive `no` commands (except `no shutdown`)
    
    Args:
        commands: List of CLI command strings from AI
        parsed_config: Dict from parse_running_config() for this device
        audit_report: Optional audit report dict
    
    Returns:
        tuple: (filtered_commands, guardrail_log)
    """
    if not commands:
        return commands, []
    
    filtered = []
    log = []
    
    # Build sets of protected resources
    existing_vlans = set(parsed_config.get('vlans', {}).keys())
    existing_vlan_names = {vid: name for vid, name in parsed_config.get('vlans', {}).items() if name}
    
    existing_ifaces_with_ip = set()
    for iface_name, iface in parsed_config.get('interfaces', {}).items():
        if iface.get('ip') and iface['ip'] != '0.0.0.0':
            existing_ifaces_with_ip.add(iface_name.lower())
    
    ospf_process = parsed_config.get('ospf', {}).get('process_id')
    
    # Add VLANs from audit report if available
    if audit_report:
        vlan_facts = audit_report.get('vlan', {}).get('facts', [])
        for fact in vlan_facts:
            if 'IMMUTABLE' in fact:
                # Extract VLAN ID from fact string
                m = re.match(r"Pre-configured VLAN (\d+)", fact)
                if m:
                    existing_vlans.add(int(m.group(1)))
    
    current_iface = None
    skip_until_section_end = False
    
    for cmd in commands:
        stripped = cmd.strip()
        lower = stripped.lower()
        
        # Track current interface context
        m = re.match(r'^interface\s+(.+)', stripped, re.I)
        if m:
            current_iface = m.group(1).strip()
            skip_until_section_end = False
        
        # Reset context on section boundaries
        if lower in ('exit', 'end', '!'):
            current_iface = None
            skip_until_section_end = False
        
        if skip_until_section_end:
            log.append(f"[GUARDRAIL] DROPPED (section skip): {stripped}")
            continue
        
        # Rule 1: Block destructive `no` commands (except `no shutdown`)
        if lower.startswith('no ') and lower != 'no shutdown':
            # Allow `no switchport` (needed for L3 ports)
            if lower == 'no switchport':
                filtered.append(cmd)
                continue
            
            # Block `no vlan X` if VLAN is pre-configured
            m = re.match(r'^no\s+vlan\s+(\d+)', stripped, re.I)
            if m and int(m.group(1)) in existing_vlans:
                log.append(f"[GUARDRAIL] BLOCKED: '{stripped}' — VLAN {m.group(1)} is pre-configured (IMMUTABLE)")
                continue
            
            # Block `no ip address` on interfaces with anchored IPs
            if lower == 'no ip address' and current_iface and current_iface.lower() in existing_ifaces_with_ip:
                log.append(f"[GUARDRAIL] BLOCKED: '{stripped}' on {current_iface} — has immutable IP anchor")
                continue
            
            # Block `no router ospf X` if it matches existing process
            m = re.match(r'^no\s+router\s+ospf\s+(\d+)', stripped, re.I)
            if m and ospf_process and int(m.group(1)) == ospf_process:
                log.append(f"[GUARDRAIL] BLOCKED: '{stripped}' — OSPF process {ospf_process} is pre-configured")
                skip_until_section_end = True
                continue
            
            # Allow other `no` commands (e.g., `no ip domain-lookup`)
            filtered.append(cmd)
            continue
        
        # Rule 2: Block VLAN rename if VLAN already has a name
        m = re.match(r'^name\s+(\S+)', stripped, re.I)
        if m:
            # Check if we're inside a vlan section
            # Look back to find the vlan number
            for prev_cmd in reversed(filtered[-5:]):
                vm = re.match(r'^vlan\s+(\d+)', prev_cmd.strip(), re.I)
                if vm:
                    vid = int(vm.group(1))
                    if vid in existing_vlan_names and existing_vlan_names[vid]:
                        existing_name = existing_vlan_names[vid]
                        new_name = m.group(1)
                        if new_name.lower() != existing_name.lower():
                            log.append(f"[GUARDRAIL] BLOCKED: VLAN {vid} rename from '{existing_name}' to '{new_name}' — name is IMMUTABLE")
                            continue
                    break
        
        # Rule 3: Block IP overwrite on anchored interfaces
        m = re.match(r'^ip\s+address\s+(\S+)\s+(\S+)', stripped, re.I)
        if m and current_iface and current_iface.lower() in existing_ifaces_with_ip:
            existing_ip = None
            for iface_name, iface in parsed_config.get('interfaces', {}).items():
                if iface_name.lower() == current_iface.lower():
                    existing_ip = iface.get('ip')
                    break
            if existing_ip and existing_ip != m.group(1):
                log.append(f"[GUARDRAIL] BLOCKED: IP change on {current_iface} from {existing_ip} to {m.group(1)} — IP is IMMUTABLE")
                continue
        
        filtered.append(cmd)
    
    if log:
        print(f"\n{'=' * 50}")
        print(f"GUARDRAIL REPORT ({len(log)} interventions):")
        for entry in log:
            print(f"  {entry}")
        print(f"{'=' * 50}\n")
    
    return filtered, log


def commands_to_running_config(commands, existing_config=''):
    """
    Convert a list of CLI commands into a running-config format.
    
    This simulates what the IOS would produce after executing the commands.
    In practice, we'll merge the commands into the existing config.
    
    Args:
        commands: List of CLI command strings
        existing_config: Existing running-config text
        
    Returns:
        str: Updated running-config text
    """
    # Parse existing config sections
    config_lines = []
    if existing_config:
        config_lines = existing_config.strip().split('\n')
    
    # Build new config from commands
    new_config_lines = []
    current_section = None  # Tracks if we're inside interface/router/vlan/line block
    
    # Section-starting patterns (these create config blocks)
    section_patterns = re.compile(
        r'^(interface\s+|router\s+|line\s+|ip dhcp pool\s+|ip access-list\s+|vlan\s+\d|spanning-tree\s+)',
        re.IGNORECASE
    )
    
    # Commands to skip entirely (not part of running-config)
    skip_commands = {
        'enable', 'en', 'conf t', 'configure terminal', 'config t',
        'end', 'write memory', 'write mem', 'wr',
        'copy running-config startup-config', 'copy run start', 'do wr'
    }
    
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue
        
        cmd_lower = cmd.lower()
        
        # Skip mode-entry/save commands
        if cmd_lower in skip_commands:
            if cmd_lower in ('configure terminal', 'conf t', 'config t'):
                pass  # Entering config mode, don't reset section
            elif cmd_lower == 'end':
                current_section = None
            continue
        
        # 'exit' means go back one level — reset current section
        if cmd_lower == 'exit':
            current_section = None
            continue
        
        # Expand 'interface range' into individual interfaces
        range_match = re.match(r'^interface range\s+(.+)', cmd, re.IGNORECASE)
        if range_match:
            # Parse range like "GigabitEthernet1/0/1-2" or "Gi1/0/1-2, Gi1/0/3-4"
            range_spec = range_match.group(1)
            expanded = _expand_interface_range(range_spec)
            if expanded:
                # Store the expanded interfaces; subsequent commands apply to ALL of them
                current_section = '__range__'
                new_config_lines.append('!__RANGE_START__!' + ','.join(expanded))
                continue
            else:
                # Fallback: treat as single interface
                current_section = cmd
                new_config_lines.append('!')
                new_config_lines.append(cmd)
                continue
        
        # Detect section headers
        if section_patterns.match(cmd):
            current_section = cmd
            new_config_lines.append('!')
            new_config_lines.append(cmd)
        elif cmd_lower.startswith('hostname '):
            current_section = None
            new_config_lines.insert(0, cmd)
        elif cmd_lower.startswith('ip routing') or cmd_lower.startswith('ip dhcp excluded') or cmd_lower.startswith('ip default-gateway') or cmd_lower.startswith('enable ') or cmd_lower.startswith('service ') or cmd_lower.startswith('no service'):
            # These are GLOBAL commands even if typed inside a section
            new_config_lines.append(cmd)
        else:
            # Sub-command: indent if inside a section
            if current_section and current_section != '__range__':
                new_config_lines.append(' ' + cmd)
            elif current_section == '__range__':
                new_config_lines.append(' ' + cmd)  # Will be expanded later
            else:
                new_config_lines.append(cmd)
    
    # Post-process: expand __RANGE_START__ markers
    final_lines = []
    i = 0
    while i < len(new_config_lines):
        line = new_config_lines[i]
        if line.startswith('!__RANGE_START__!'):
            ifaces = line[len('!__RANGE_START__!'):].split(',')
            # Collect all sub-commands until next section or range end
            sub_cmds = []
            i += 1
            while i < len(new_config_lines):
                next_line = new_config_lines[i]
                if next_line.startswith('!') or section_patterns.match(next_line.strip()):
                    break
                sub_cmds.append(next_line)
                i += 1
            # Emit each interface with the same sub-commands
            for iface in ifaces:
                final_lines.append('!')
                final_lines.append(f'interface {iface}')
                final_lines.extend(sub_cmds)
        else:
            final_lines.append(line)
            i += 1
    
    new_config_lines = final_lines
    
    # If we have an existing config, try to merge intelligently
    if config_lines and len(config_lines) > 5:
        return _merge_configs(config_lines, new_config_lines)
    
    # Build a fresh config
    final_lines = ['!']
    final_lines.extend(new_config_lines)
    final_lines.append('!')
    final_lines.append('end')
    
    return '\n'.join(final_lines)


def _merge_configs(existing_lines, new_lines):
    """
    Merge new configuration lines into an existing running-config.
    
    CRITICAL: Packet Tracer reads the FIRST occurrence of each interface
    section and IGNORES duplicates. So we must INJECT new commands INTO
    the existing interface blocks, not append them at the end.
    
    Strategy:
    1. Parse existing config into ordered sections (keyed by section header)
    2. Parse AI commands into sections
    3. For matching interfaces, inject AI commands into existing section
    4. For new sections (vlans, dhcp, etc.), insert them at the right place
    """
    
    # ── Step 1: Parse existing config into sections ──
    # Each section is (header, [sub-commands])
    # "header" is like "interface GigabitEthernet0/1" or "__global__"
    existing_sections = []  # list of (header_line, [body_lines])
    current_header = '__global__'
    current_body = []
    
    # Track which interfaces have protected IPs
    protected_ips = set()
    
    for line in existing_lines:
        line_s = line.strip()
        
        # Detect section headers
        if re.match(r'^(interface |router |line |ip dhcp |ip access-list |vlan |spanning-tree )', line_s, re.IGNORECASE):
            # Save previous section
            existing_sections.append((current_header, current_body))
            current_header = line_s
            current_body = []
        elif line_s == '!' and current_header != '__global__':
            # End of current section
            existing_sections.append((current_header, current_body))
            current_header = '__global__'
            current_body = []
        elif line_s.lower() == 'end':
            continue  # Skip 'end', we'll add it at the end
        else:
            current_body.append(line)
            # Track protected IPs
            if current_header.startswith('interface ') and line_s.startswith('ip address ') and 'no ip address' not in line_s:
                protected_ips.add(current_header)
    
    # Don't forget the last section
    if current_body or current_header != '__global__':
        existing_sections.append((current_header, current_body))
    
    # Build a lookup: header -> index in existing_sections
    section_index = {}
    for i, (header, _) in enumerate(existing_sections):
        if header not in section_index:  # Keep first occurrence
            section_index[header] = i
    
    # ── Step 2: Parse AI commands into sections ──
    ai_sections = []
    current_header = '__global__'
    current_body = []
    
    for line in new_lines:
        line_s = line.strip()
        
        if re.match(r'^(interface |router |line |ip dhcp |ip access-list |vlan |spanning-tree )', line_s, re.IGNORECASE):
            if current_body or current_header != '__global__':
                ai_sections.append((current_header, current_body))
            current_header = line_s
            current_body = []
        elif line_s == '!':
            if current_header != '__global__':
                ai_sections.append((current_header, current_body))
                current_header = '__global__'
                current_body = []
        else:
            current_body.append(line)
    
    if current_body or current_header != '__global__':
        ai_sections.append((current_header, current_body))
    
    # ── Step 3: Merge AI sections into existing config ──
    new_sections_to_append = []  # Sections that don't exist yet
    
    for ai_header, ai_body in ai_sections:
        # Reorder ai_body to ensure channel-group commands are executed LAST
        # within an interface block to prevent EtherChannel misconfigurations in PT.
        if ai_header.startswith('interface '):
            normal_cmds = []
            channel_cmds = []
            for cmd in ai_body:
                if cmd.strip().lower().startswith('channel-group'):
                    channel_cmds.append(cmd)
                else:
                    normal_cmds.append(cmd)
            ai_body = normal_cmds + channel_cmds

        if ai_header == '__global__':
            # Global commands (hostname, ip routing, etc.) - add to first global section
            for i, (h, b) in enumerate(existing_sections):
                if h == '__global__':
                    # Filter and append global commands
                    for cmd in ai_body:
                        cmd_s = cmd.strip()
                        if cmd_s and cmd_s not in [l.strip() for l in b]:
                            existing_sections[i] = (h, b + [cmd])
                    break
            else:
                new_sections_to_append.append((ai_header, ai_body))
            continue
        
        if ai_header in section_index:
            # ── INJECT into existing section ──
            idx = section_index[ai_header]
            _, existing_body = existing_sections[idx]
            
            for cmd in ai_body:
                cmd_s = cmd.strip()
                
                # IP Firewall: block IP changes on protected interfaces
                if ai_header.startswith('interface ') and cmd_s.startswith('ip address ') and 'no ip address' not in cmd_s:
                    if ai_header in protected_ips:
                        print(f"[!] CLI FIREWALL: Blocked IP change on {ai_header}")
                        continue
                
                # Shutdown firewall
                if cmd_s == 'shutdown':
                    print(f"[!] CLI FIREWALL: Blocked shutdown on {ai_header}")
                    continue
                
                # Don't duplicate existing commands
                if cmd_s not in [l.strip() for l in existing_body]:
                    existing_body.append(cmd)
            
            existing_sections[idx] = (ai_header, existing_body)
        else:
            # ── New section (doesn't exist in original config) ──
            # Apply firewall to new sections too
            filtered_body = []
            for cmd in ai_body:
                cmd_s = cmd.strip()
                if cmd_s == 'shutdown':
                    print(f"[!] CLI FIREWALL: Blocked shutdown on {ai_header}")
                    continue
                filtered_body.append(cmd)
            
            new_sections_to_append.append((ai_header, filtered_body))
    
    # ── Step 4: Reconstruct the config ──
    result = []
    
    for header, body in existing_sections:
        if header == '__global__':
            for line in body:
                result.append(line)
        else:
            result.append(header)
            for line in body:
                result.append(line)
            result.append('!')
    
    # Append new sections that didn't exist before
    if new_sections_to_append:
        result.append('! === CiscoLabAI New Sections ===')
        for header, body in new_sections_to_append:
            if header == '__global__':
                for line in body:
                    result.append(line)
            else:
                result.append(header)
                for line in body:
                    result.append(line)
                result.append('!')
    
    result.append('end')
    
    return '\n'.join(result)


def _write_config_as_lines(config_elem, config_text):
    """
    Write config text into an XML element using <LINE> child elements.
    
    Packet Tracer stores running-config and startup-config as:
        <RUNNINGCONFIG>
            <LINE>hostname Router</LINE>
            <LINE>!</LINE>
            <LINE>interface GigabitEthernet0/0</LINE>
            ...
        </RUNNINGCONFIG>
    
    Setting config_elem.text = "..." does NOT work — PT ignores .text
    and only reads <LINE> children. This is the correct method.
    """
    # Step 1: Remove ALL existing <LINE> children
    for child in list(config_elem):
        if child.tag == 'LINE':
            config_elem.remove(child)
    
    # Step 2: Clear any .text content (PT doesn't use it, but keep clean)
    config_elem.text = None
    
    # Step 3: Write each line of the new config as a <LINE> element
    for line in config_text.split('\n'):
        line_elem = ET.SubElement(config_elem, 'LINE')
        line_elem.text = line


def set_device_config(root, device_name, running_config_text):
    """
    Set the running-config and startup-config for a device in the XML.
    
    CRITICAL: Packet Tracer reads config from <LINE> child elements,
    NOT from the element's .text property. We must write each config
    line as a separate <LINE> element.
    
    CRITICAL: PT8 files contain DUPLICATE device elements (one in
    logical workspace, one in physical workspace). We must update
    ALL instances to ensure PT reads the correct config.
    
    Args:
        root: XML root element
        device_name: Name of the device
        running_config_text: The full running-config text
        
    Returns:
        bool: True if successful
    """
    # Find ALL device elements with this name (not just the first)
    found_count = 0
    
    for device in root.findall('.//DEVICE'):
        engine = device.find('.//ENGINE') or device
        name_elem = engine.find('.//NAME') or engine.find('.//name')
        if name_elem is None:
            continue
        
        dev_name = (name_elem.text or '').strip()
        # Exact match or case-insensitive match
        if dev_name != device_name and dev_name.lower() != device_name.lower():
            continue
        
        # Set running config using LINE elements
        config_elem = engine.find('.//RUNNINGCONFIG')
        if config_elem is None:
            config_elem = engine.find('.//runningconfig')
        if config_elem is None:
            config_elem = ET.SubElement(engine, 'RUNNINGCONFIG')
        _write_config_as_lines(config_elem, running_config_text)
        
        # Also set startup config (so it persists after reload)
        startup_elem = engine.find('.//STARTUPCONFIG')
        if startup_elem is None:
            startup_elem = engine.find('.//startupconfig')
        if startup_elem is None:
            startup_elem = ET.SubElement(engine, 'STARTUPCONFIG')
        _write_config_as_lines(startup_elem, running_config_text)
        
        found_count += 1
    
    if found_count == 0:
        print(f"[!] Device not found: {device_name}")
        return False
    
    line_count = len(running_config_text.split('\n'))
    print(f"[+] Set config for {device_name} ({line_count} lines as <LINE> elements, {found_count} XML instances updated)")
    return True


def set_pc_ip_config(root, device_name, ip=None, mask=None, gateway=None, dns=None):
    """
    Set IP configuration for a PC or Server device.
    
    PCs in Packet Tracer store their IP settings differently from routers/switches.
    
    Args:
        root: XML root element
        device_name: Name of the PC/Server
        ip: IP address
        mask: Subnet mask
        gateway: Default gateway
        dns: DNS server address
        
    Returns:
        bool: True if successful
    """
    device = find_device_element(root, device_name)
    if device is None:
        print(f"[!] PC/Server not found: {device_name}")
        return False
    
    engine = device.find('.//ENGINE') or device
    
    # Find or create the network config section for the PC
    # PCs store IP in various places depending on PT version
    # Try common paths
    
    # Method 1: Direct IP elements
    for port in engine.findall('.//PORT') + engine.findall('.//port'):
        ip_elem = port.find('.//IP') or port.find('.//ip')
        if ip_elem is not None or port.find('.//LINK') is not None:
            if ip and ip_elem is None:
                ip_elem = ET.SubElement(port, 'IP')
            if ip_elem is not None and ip:
                ip_elem.text = ip
            
            mask_elem = port.find('.//MASK') or port.find('.//mask') or port.find('.//SUBNET')
            if mask and mask_elem is None:
                mask_elem = ET.SubElement(port, 'MASK')
            if mask_elem is not None and mask:
                mask_elem.text = mask
            
            gw_elem = port.find('.//GATEWAY') or port.find('.//gateway')
            if gateway and gw_elem is None:
                gw_elem = ET.SubElement(port, 'GATEWAY')
            if gw_elem is not None and gateway:
                gw_elem.text = gateway
            
            dns_elem = port.find('.//DNS') or port.find('.//dns')
            if dns and dns_elem is None:
                dns_elem = ET.SubElement(port, 'DNS')
            if dns_elem is not None and dns:
                dns_elem.text = dns
            
            print(f"[+] Set PC config for {device_name}: IP={ip}, Mask={mask}, GW={gateway}, DNS={dns}")
            return True
    
    # Method 2: Config section
    config_text = f"""
ip address {ip or '0.0.0.0'} {mask or '255.255.255.0'}
ip default-gateway {gateway or '0.0.0.0'}
ip dns {dns or '0.0.0.0'}
"""
    config_elem = engine.find('.//RUNNINGCONFIG')
    if config_elem is None:
        config_elem = ET.SubElement(engine, 'RUNNINGCONFIG')
    config_elem.text = config_text.strip()
    
    print(f"[+] Set PC config for {device_name} via RUNNINGCONFIG")
    return True


def inject_all_configs(root, ai_solution):
    """
    Apply all configurations from the AI solution to the XML tree.
    
    Args:
        root: XML root element
        ai_solution: Parsed AI response dict with 'devices' key
        
    Returns:
        dict: Results summary with successes and failures
    """
    results = {
        'configured': [],
        'failed': [],
        'skipped': [],
    }
    
    devices = ai_solution.get('devices', {})
    
    for device_name, device_config in devices.items():
        device_type = device_config.get('type', '').lower()
        
        if device_type in ['pc', 'server']:
            # Handle PC/Server IP configuration
            ip_config = device_config.get('ip_config', {})
            if ip_config:
                success = set_pc_ip_config(
                    root,
                    device_name,
                    ip=ip_config.get('ip'),
                    mask=ip_config.get('mask'),
                    gateway=ip_config.get('gateway'),
                    dns=ip_config.get('dns')
                )
                if success:
                    results['configured'].append(device_name)
                else:
                    results['failed'].append(device_name)
            else:
                results['skipped'].append(device_name)
        
        elif device_type in ['router', 'switch']:
            # Handle router/switch CLI configuration
            commands = device_config.get('commands', [])
            if commands:
                existing_config = ''
                device_elem = find_device_element(root, device_name)
                if device_elem is not None:
                    engine = device_elem.find('.//ENGINE') or device_elem
                    cfg = engine.find('.//RUNNINGCONFIG')
                    if cfg is not None and cfg.text:
                        existing_config = cfg.text
                
                new_config = commands_to_running_config(commands, existing_config)
                success = set_device_config(root, device_name, new_config)
                if success:
                    results['configured'].append(device_name)
                else:
                    results['failed'].append(device_name)
            else:
                results['skipped'].append(device_name)
        
        else:
            # Unknown device type - try as router/switch
            commands = device_config.get('commands', [])
            if commands:
                new_config = commands_to_running_config(commands)
                success = set_device_config(root, device_name, new_config)
                if success:
                    results['configured'].append(device_name)
                else:
                    results['failed'].append(device_name)

    return results


def apply_solution_to_xml(xml_string, solution, ctx_devices, audit_report=None,
                          guardrails=True):
    """
    Inject an AI solution into the PKA XML, scoped per <DEVICE> block.

    This is the single source of truth for applying a solution — used both by the
    /api/apply endpoint and by the refinement loop (solver.py), so they stay in
    lockstep. Every device type is eligible; how to inject is decided by behaviour
    (block has a running-config -> IOS commands; otherwise -> IP settings).

    Args:
        xml_string:   the original decoded PKA XML
        solution:     parsed AI solution {'devices': {name: {commands|ip_config}}}
        ctx_devices:  context['devices'] (authoritative names + running-configs)
        audit_report: optional audit dict for guardrails

    Returns:
        (modified_xml, config_results)
    """
    import re as re_mod
    from network_auditor import parse_running_config

    modified_xml = xml_string
    config_results = {'configured': [], 'failed': [], 'skipped': []}

    xml_device_names = [d['name'] for d in ctx_devices if d.get('name')]
    name_to_runcfg = {d['name']: d.get('running_config', '') for d in ctx_devices}

    def find_xml_name(ai_name):
        if ai_name in xml_device_names:
            return ai_name
        for xn in xml_device_names:
            if xn.lower() == ai_name.lower():
                return xn
        ai_clean = ai_name.lower().replace('_', '').replace('-', '').replace(' ', '')
        for xn in xml_device_names:
            if xn.lower().replace('_', '').replace('-', '').replace(' ', '') == ai_clean:
                return xn
        for xn in xml_device_names:
            if ai_name.lower() in xn.lower() or xn.lower() in ai_name.lower():
                return xn
        return None

    # Split into flat, self-contained <DEVICE> blocks (PT keeps ~two copies).
    blocks = modified_xml.split('<DEVICE>')
    block_name_re = re_mod.compile(
        r'<TYPE[^>]*>[^<]*</TYPE>\s*<NAME[^>]*>\s*(.*?)\s*</NAME>',
        re_mod.DOTALL | re_mod.IGNORECASE)

    def block_name(blk):
        m = block_name_re.search(blk)
        return m.group(1).strip() if m else None

    block_names = [None] + [block_name(b) for b in blocks[1:]]

    def patch_tag(text, tag, val):
        pattern = r'<(' + tag + r')(?:>.*?</\1>|\s*/>)'
        return re_mod.sub(pattern, f'<{tag}>{val}</{tag}>', text, count=1, flags=re_mod.DOTALL)

    def has_existing_value(text, tag):
        m = re_mod.search(r'<' + tag + r'>([^<]+)</' + tag + r'>', text)
        if m:
            val = m.group(1).strip()
            if val and val != '0.0.0.0' and val != '::':
                return True
        return False

    def inject_ip_block(dev_text, ip_config, name):
        ip_capable = ('<IP>' in dev_text or '<IP/>' in dev_text or '<IP ' in dev_text
                      or '<IP_ADDRESS>' in dev_text or '<IP_ADDRESS/>' in dev_text)
        ip = ip_config.get('ip_address')
        if ip:
            if not has_existing_value(dev_text, 'IP'):
                if '<IP>' in dev_text or '<IP/>' in dev_text or '<IP ' in dev_text:
                    dev_text = patch_tag(dev_text, 'IP', ip)
                elif '<IP_ADDRESS>' in dev_text or '<IP_ADDRESS/>' in dev_text:
                    dev_text = patch_tag(dev_text, 'IP_ADDRESS', ip)
        mask = ip_config.get('subnet_mask')
        if mask and not has_existing_value(dev_text, 'SUBNET'):
            if '<SUBNET>' in dev_text or '<SUBNET/>' in dev_text or '<SUBNET ' in dev_text:
                dev_text = patch_tag(dev_text, 'SUBNET', mask)
            elif '<SUBNET_MASK>' in dev_text or '<SUBNET_MASK/>' in dev_text:
                dev_text = patch_tag(dev_text, 'SUBNET_MASK', mask)
        gw = ip_config.get('default_gateway')
        if gw:
            if not has_existing_value(dev_text, 'GATEWAY'):
                dev_text = patch_tag(dev_text, 'GATEWAY', gw)
                dev_text = patch_tag(dev_text, 'DEFAULT_GATEWAY', gw)
            if not has_existing_value(dev_text, 'PORT_GATEWAY'):
                dev_text = patch_tag(dev_text, 'PORT_GATEWAY', gw)
        ipv6 = ip_config.get('ipv6_address')
        if ipv6:
            existing = re_mod.search(r'<ADDRESS>([^<]+)</ADDRESS>', dev_text)
            if not (existing and existing.group(1).strip() and existing.group(1).strip() != '::'):
                parts = ipv6.split('/')
                addr = parts[0]
                prefix = parts[1] if len(parts) > 1 else '64'
                ipv6_xml = f'<IPV6_ADDRESS>\n            <ADDRESS>{addr}</ADDRESS>\n            <PREFIX>{prefix}</PREFIX>\n            <TYPE>0</TYPE>\n           </IPV6_ADDRESS>'
                dev_text = re_mod.sub(r'<IPV6_ADDRESSES>.*?</IPV6_ADDRESSES>', f'<IPV6_ADDRESSES>\n           {ipv6_xml}\n          </IPV6_ADDRESSES>', dev_text, flags=re_mod.DOTALL, count=1)
        ipv6_gw = ip_config.get('ipv6_gateway')
        if ipv6_gw:
            if not has_existing_value(dev_text, 'GATEWAYV6'):
                dev_text = patch_tag(dev_text, 'GATEWAYV6', ipv6_gw)
            if not has_existing_value(dev_text, 'IPV6_PORT_GATEWAY'):
                dev_text = patch_tag(dev_text, 'IPV6_PORT_GATEWAY', ipv6_gw)
        return dev_text, ip_capable

    def inject_config_block(dev_text, commands):
        state = {'replaced': False}

        def repl(match):
            state['replaced'] = True
            plain_existing = match.group(2).replace('<LINE>', '').replace('</LINE>', '').strip()
            new_plain = commands_to_running_config(commands, plain_existing)
            new_lines = []
            for line in new_plain.split('\n'):
                esc = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                new_lines.append(f'\n       <LINE>{esc}</LINE>')
            return match.group(1) + ''.join(new_lines) + '\n      ' + match.group(3)

        dev_text = re_mod.sub(r'(<RUNNINGCONFIG>)(.*?)(</RUNNINGCONFIG>)', repl, dev_text, flags=re_mod.DOTALL)
        dev_text = re_mod.sub(r'(<STARTUPCONFIG>)(.*?)(</STARTUPCONFIG>)', repl, dev_text, flags=re_mod.DOTALL)
        return dev_text, state['replaced']

    for ai_device_name, device_config in solution.get('devices', {}).items():
        commands = device_config.get('commands', [])
        ip_config = device_config.get('ip_config', {})

        real_name = find_xml_name(ai_device_name)
        if not real_name:
            config_results['failed'].append(ai_device_name)
            continue

        if commands and guardrails:
            # Guardrails protect existing config on the first/single-shot pass.
            # The refinement loop disables them so the LLM can CORRECT verifier-
            # flagged errors in existing config (e.g. a duplicate IP).
            parsed = parse_running_config(name_to_runcfg.get(real_name, ''))
            commands, guardrail_log = validate_commands(commands, parsed, audit_report)
            if guardrail_log:
                config_results.setdefault('guardrail_log', []).extend(guardrail_log)

        matched = False
        for i in range(1, len(blocks)):
            if not block_names[i] or block_names[i].lower() != real_name.lower():
                continue
            if commands and '<RUNNINGCONFIG>' in blocks[i]:
                blocks[i], ok = inject_config_block(blocks[i], commands)
                matched = matched or ok
            elif ip_config:
                blocks[i], ok = inject_ip_block(blocks[i], ip_config, real_name)
                matched = matched or ok

        if matched:
            config_results['configured'].append(real_name)
        elif not commands and not ip_config:
            config_results['skipped'].append(ai_device_name)
        else:
            config_results['failed'].append(ai_device_name)

    modified_xml = '<DEVICE>'.join(blocks)
    return modified_xml, config_results
