"""Check the exact running configs inside the PKA to see what is actually injected."""
import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
import xml.etree.ElementTree as ET
from pka_parser import decode_pka

# Find the most recently uploaded/solved file in uploads directory
uploads_dir = 'uploads'
try:
    files = [f for f in os.listdir(uploads_dir) if f.endswith('.pka')]
    files.sort(key=lambda x: os.path.getmtime(os.path.join(uploads_dir, x)), reverse=True)
    if not files:
        print("No PKA files found.")
        sys.exit(0)
    pka_path = os.path.join(uploads_dir, files[0])
    print(f"Checking file: {pka_path}")
    
    xml_string = decode_pka(pka_path)
    xml_string = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_string)
    root = ET.fromstring(xml_string)
    
    targets = ['MLS-D', 'SW-A', 'SW_B', 'Edge_router']
    
    for device in root.findall('.//DEVICE'):
        engine = device.find('ENGINE')
        if engine is None:
            continue
        name_el = engine.find('NAME')
        if name_el is None:
            continue
            
        name = name_el.text
        if name not in targets:
            continue
            
        print(f"\n{'='*60}")
        print(f"DEVICE: {name}")
        
        rc = engine.find('.//RUNNINGCONFIG')
        if rc is None:
            print("  No RUNNINGCONFIG found!")
            continue
            
        lines = rc.findall('LINE')
        config_text = '\n'.join((l.text or '') for l in lines)
        
        # Look for the interface configs
        for section in config_text.split('interface '):
            if section.startswith('GigabitEthernet1/0/1') or section.startswith('GigabitEthernet0/1'):
                print(f"\n--- interface {section.split('!')[0].strip()} ---")
        
except Exception as e:
    print(f"Error: {e}")
