"""
topology_modifier.py - Add devices, modules, and connections to PKA XML

Enables "Full Auto" mode where the AI can modify the network topology:
- Add new devices (routers, switches, PCs, servers)
- Add interface modules (HWIC-2T, NM-1FE-TX, etc.)
- Create cable connections between devices
"""

import xml.etree.ElementTree as ET
import copy


# ─── Device XML Templates ─────────────────────────────────────────────────
# These are simplified templates. Real PKA files have more detail,
# but PT is forgiving and will fill in defaults for missing elements.

DEVICE_TEMPLATES = {
    'Router': {
        '1841': {
            'type': 'Router',
            'model': '1841',
            'default_ports': [
                {'name': 'FastEthernet0/0', 'type': 'FastEthernet'},
                {'name': 'FastEthernet0/1', 'type': 'FastEthernet'},
            ],
            'module_slots': 2,
        },
        '2811': {
            'type': 'Router',
            'model': '2811',
            'default_ports': [
                {'name': 'FastEthernet0/0', 'type': 'FastEthernet'},
                {'name': 'FastEthernet0/1', 'type': 'FastEthernet'},
            ],
            'module_slots': 2,
        },
        '2901': {
            'type': 'Router', 
            'model': '2901',
            'default_ports': [
                {'name': 'GigabitEthernet0/0', 'type': 'GigabitEthernet'},
                {'name': 'GigabitEthernet0/1', 'type': 'GigabitEthernet'},
            ],
            'module_slots': 4,
        },
        '4321': {
            'type': 'Router',
            'model': '4321',
            'default_ports': [
                {'name': 'GigabitEthernet0/0/0', 'type': 'GigabitEthernet'},
                {'name': 'GigabitEthernet0/0/1', 'type': 'GigabitEthernet'},
            ],
            'module_slots': 2,
        },
    },
    'Switch': {
        '2960': {
            'type': 'Switch',
            'model': '2960-24TT',
            'default_ports': [
                *[{'name': f'FastEthernet0/{i}', 'type': 'FastEthernet'} for i in range(24)],
                {'name': 'GigabitEthernet0/1', 'type': 'GigabitEthernet'},
                {'name': 'GigabitEthernet0/2', 'type': 'GigabitEthernet'},
            ],
            'module_slots': 0,
        },
        '3560': {
            'type': 'Switch',
            'model': '3560-24PS',
            'default_ports': [
                *[{'name': f'FastEthernet0/{i}', 'type': 'FastEthernet'} for i in range(24)],
                {'name': 'GigabitEthernet0/1', 'type': 'GigabitEthernet'},
                {'name': 'GigabitEthernet0/2', 'type': 'GigabitEthernet'},
            ],
            'module_slots': 0,
        },
    },
    'PC': {
        'PC-PT': {
            'type': 'PC',
            'model': 'PC-PT',
            'default_ports': [
                {'name': 'FastEthernet0', 'type': 'FastEthernet'},
            ],
            'module_slots': 0,
        },
    },
    'Server': {
        'Server-PT': {
            'type': 'Server',
            'model': 'Server-PT',
            'default_ports': [
                {'name': 'FastEthernet0', 'type': 'FastEthernet'},
            ],
            'module_slots': 0,
        },
    },
    'Laptop': {
        'Laptop-PT': {
            'type': 'Laptop',
            'model': 'Laptop-PT',
            'default_ports': [
                {'name': 'FastEthernet0', 'type': 'FastEthernet'},
                {'name': 'Wireless0', 'type': 'Wireless'},
            ],
            'module_slots': 0,
        },
    },
}

# Module types that can be added to router slots
MODULE_TEMPLATES = {
    'HWIC-2T': {
        'ports': [
            {'name': 'Serial0/{slot}/0', 'type': 'Serial'},
            {'name': 'Serial0/{slot}/1', 'type': 'Serial'},
        ]
    },
    'HWIC-4ESW': {
        'ports': [
            *[{'name': f'FastEthernet0/{{slot}}/{i}', 'type': 'FastEthernet'} for i in range(4)],
        ]
    },
    'NM-1FE-TX': {
        'ports': [
            {'name': 'FastEthernet{slot}/0', 'type': 'FastEthernet'},
        ]
    },
    'NM-2FE2W': {
        'ports': [
            {'name': 'FastEthernet{slot}/0', 'type': 'FastEthernet'},
            {'name': 'FastEthernet{slot}/1', 'type': 'FastEthernet'},
        ]
    },
    'WIC-1T': {
        'ports': [
            {'name': 'Serial0/{slot}/0', 'type': 'Serial'},
        ]
    },
    'WIC-2T': {
        'ports': [
            {'name': 'Serial0/{slot}/0', 'type': 'Serial'},
            {'name': 'Serial0/{slot}/1', 'type': 'Serial'},
        ]
    },
}

# Cable type mapping
CABLE_TYPES = {
    'Copper Straight-Through': 'eStraightThrough',
    'Copper Cross-Over': 'eCrossOver',
    'Serial DCE': 'eSerialDCE',
    'Serial DTE': 'eSerialDTE',
    'Console': 'eConsole',
    'Fiber': 'eFiber',
    'Coaxial': 'eCoaxial',
    'Phone': 'ePhone',
    'Automatic': 'eAutomatic',
}


def _build_device_xml(name, device_type, model, x=300, y=300, modules=None):
    """
    Build an XML element for a new device.
    
    Args:
        name: Device hostname
        device_type: 'Router', 'Switch', 'PC', 'Server', 'Laptop'
        model: Model number (e.g., '1841', '2960', 'PC-PT')
        x, y: Position on the canvas
        modules: List of modules to add (for routers)
        
    Returns:
        Element: The DEVICE XML element
    """
    # Find the template
    template = None
    type_templates = DEVICE_TEMPLATES.get(device_type, {})
    
    for tmpl_model, tmpl in type_templates.items():
        if model.lower() in tmpl_model.lower() or tmpl_model.lower() in model.lower():
            template = tmpl
            break
    
    if template is None:
        # Use first available template for this type
        if type_templates:
            template = list(type_templates.values())[0]
        else:
            # Generic device
            template = {
                'type': device_type,
                'model': model,
                'default_ports': [{'name': 'FastEthernet0/0', 'type': 'FastEthernet'}],
                'module_slots': 0,
            }
    
    # Build the XML structure
    device_elem = ET.Element('DEVICE')
    
    # ENGINE section
    engine = ET.SubElement(device_elem, 'ENGINE')
    
    type_elem = ET.SubElement(engine, 'TYPE')
    type_elem.set('model', model)
    type_elem.text = device_type
    
    name_elem = ET.SubElement(engine, 'NAME')
    name_elem.set('translate', 'true')
    name_elem.text = name
    
    power_elem = ET.SubElement(engine, 'POWER')
    power_elem.text = 'true'
    
    desc_elem = ET.SubElement(engine, 'DESCRIPTION')
    desc_elem.text = ''
    
    # Add default module (non-removable) with ports
    module_elem = ET.SubElement(engine, 'MODULE')
    mod_type = ET.SubElement(module_elem, 'TYPE')
    mod_type.text = 'eNonRemovableModule'
    
    for port_info in template['default_ports']:
        port_elem = ET.SubElement(module_elem, 'PORT')
        port_name = ET.SubElement(port_elem, 'NAME')
        port_name.text = port_info['name']
        link_elem = ET.SubElement(port_elem, 'LINK')
        link_elem.text = 'down'
    
    # Add additional modules if specified
    if modules:
        for mod_info in modules:
            _add_module_xml(engine, mod_info.get('type', 'HWIC-2T'), mod_info.get('slot', 0))
    
    # Running config
    config_elem = ET.SubElement(engine, 'RUNNINGCONFIG')
    config_elem.text = ''
    
    startup_elem = ET.SubElement(engine, 'STARTUPCONFIG')
    startup_elem.text = ''
    
    # PHYSICALWORKSPACE section (position on canvas)
    phys = ET.SubElement(device_elem, 'PHYSICALWORKSPACE')
    dev_pos = ET.SubElement(phys, 'DEVICE')
    dev_pos.set('x', str(int(x)))
    dev_pos.set('y', str(int(y)))
    
    return device_elem


def _add_module_xml(engine_elem, module_type, slot):
    """Add a module (like HWIC-2T) to a device's engine element."""
    module_template = MODULE_TEMPLATES.get(module_type)
    if module_template is None:
        print(f"[!] Unknown module type: {module_type}")
        return
    
    module_elem = ET.SubElement(engine_elem, 'MODULE')
    mod_type = ET.SubElement(module_elem, 'TYPE')
    mod_type.text = module_type
    
    slot_elem = ET.SubElement(module_elem, 'SLOT')
    slot_elem.text = str(slot)
    
    for port_info in module_template['ports']:
        port_elem = ET.SubElement(module_elem, 'PORT')
        port_name = ET.SubElement(port_elem, 'NAME')
        port_name.text = port_info['name'].format(slot=slot)
        link_elem = ET.SubElement(port_elem, 'LINK')
        link_elem.text = 'down'


def _build_connection_xml(device1, port1, device2, port2, cable_type='Copper Straight-Through'):
    """
    Build an XML element for a cable connection.
    
    Args:
        device1, device2: Device names
        port1, port2: Port/interface names
        cable_type: Type of cable
        
    Returns:
        Element: The CONNECTION XML element
    """
    conn_elem = ET.Element('CONNECTION')
    
    type_elem = ET.SubElement(conn_elem, 'TYPE')
    type_elem.text = CABLE_TYPES.get(cable_type, cable_type)
    
    ep1 = ET.SubElement(conn_elem, 'ENDPOINT1')
    dev1_elem = ET.SubElement(ep1, 'DEVICE')
    dev1_elem.text = device1
    port1_elem = ET.SubElement(ep1, 'PORT')
    port1_elem.text = port1
    
    ep2 = ET.SubElement(conn_elem, 'ENDPOINT2')
    dev2_elem = ET.SubElement(ep2, 'DEVICE')
    dev2_elem.text = device2
    port2_elem = ET.SubElement(ep2, 'PORT')
    port2_elem.text = port2
    
    return conn_elem


def add_device(root, name, device_type, model, x=300, y=300, modules=None):
    """
    Add a new device to the XML topology.
    
    Args:
        root: XML root element
        name: Device hostname
        device_type: 'Router', 'Switch', 'PC', 'Server', 'Laptop'
        model: Model number
        x, y: Canvas position
        modules: List of dicts with 'type' and 'slot' keys
        
    Returns:
        bool: True if successful
    """
    # Find the DEVICES container
    devices_container = root.find('.//DEVICES')
    if devices_container is None:
        network = root.find('.//NETWORK')
        if network is None:
            network = ET.SubElement(root, 'NETWORK')
        devices_container = ET.SubElement(network, 'DEVICES')
    
    device_elem = _build_device_xml(name, device_type, model, x, y, modules)
    devices_container.append(device_elem)
    
    print(f"[+] Added device: {name} ({device_type} {model}) at ({x}, {y})")
    return True


def add_module_to_device(root, device_name, module_type, slot):
    """
    Add a module to an existing device.
    
    Args:
        root: XML root element
        device_name: Name of the device
        module_type: Module type (e.g., 'HWIC-2T')
        slot: Slot number
        
    Returns:
        bool: True if successful
    """
    from config_injector import find_device_element
    
    device = find_device_element(root, device_name)
    if device is None:
        print(f"[!] Device not found: {device_name}")
        return False
    
    engine = device.find('.//ENGINE') or device
    _add_module_xml(engine, module_type, slot)
    
    print(f"[+] Added module {module_type} to {device_name} slot {slot}")
    return True


def add_connection(root, device1, port1, device2, port2, cable_type='Copper Straight-Through'):
    """
    Add a cable connection between two devices.
    
    Args:
        root: XML root element
        device1, device2: Device names
        port1, port2: Port/interface names
        cable_type: Type of cable
        
    Returns:
        bool: True if successful
    """
    # Find the CONNECTIONS container (or LINKS)
    connections_container = root.find('.//CONNECTIONS')
    if connections_container is None:
        connections_container = root.find('.//LINKS')
    if connections_container is None:
        network = root.find('.//NETWORK')
        if network is None:
            network = ET.SubElement(root, 'NETWORK')
        connections_container = ET.SubElement(network, 'CONNECTIONS')
    
    conn_elem = _build_connection_xml(device1, port1, device2, port2, cable_type)
    connections_container.append(conn_elem)
    
    print(f"[+] Connected: {device1}:{port1} <--{cable_type}--> {device2}:{port2}")
    return True


def apply_topology_changes(root, topology_changes):
    """
    Apply all topology changes from the AI solution.
    
    Args:
        root: XML root element
        topology_changes: Dict with 'add_devices' and 'add_connections' lists
        
    Returns:
        dict: Results summary
    """
    results = {
        'devices_added': [],
        'connections_added': [],
        'errors': [],
    }
    
    if topology_changes is None:
        return results
    
    # Add devices
    for dev in topology_changes.get('add_devices', []):
        try:
            success = add_device(
                root,
                name=dev.get('name', 'NewDevice'),
                device_type=dev.get('type', 'Router'),
                model=dev.get('model', '1841'),
                x=dev.get('x', 300),
                y=dev.get('y', 300),
                modules=dev.get('modules'),
            )
            if success:
                results['devices_added'].append(dev.get('name'))
        except Exception as e:
            results['errors'].append(f"Failed to add device {dev.get('name')}: {e}")
    
    # Add connections
    for conn in topology_changes.get('add_connections', []):
        try:
            success = add_connection(
                root,
                device1=conn.get('device1', ''),
                port1=conn.get('port1', ''),
                device2=conn.get('device2', ''),
                port2=conn.get('port2', ''),
                cable_type=conn.get('cable_type', 'Copper Straight-Through'),
            )
            if success:
                results['connections_added'].append(
                    f"{conn.get('device1')}:{conn.get('port1')} <-> {conn.get('device2')}:{conn.get('port2')}"
                )
        except Exception as e:
            results['errors'].append(f"Failed to add connection: {e}")
    
    return results
