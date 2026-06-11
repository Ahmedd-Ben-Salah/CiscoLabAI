"""Dump full configs for SW-A and MLS-D from the PKA."""
import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
import xml.etree.ElementTree as ET
from pka_parser import decode_pka

uploads_dir = 'uploads'
files = [f for f in os.listdir(uploads_dir) if f.endswith('.pka')]
files.sort(key=lambda x: os.path.getmtime(os.path.join(uploads_dir, x)), reverse=True)
pka_path = os.path.join(uploads_dir, files[0])
print(f"Checking file: {pka_path}")

xml_string = decode_pka(pka_path)
xml_string = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_string)
root = ET.fromstring(xml_string)

for device in root.findall('.//DEVICE'):
    engine = device.find('ENGINE')
    if engine is None: continue
    name_el = engine.find('NAME')
    if name_el is None: continue
    name = name_el.text
    if name not in ['SW-A', 'MLS-D']: continue
        
    print(f"\n{'='*80}")
    print(f"DEVICE: {name}")
    print(f"{'='*80}")
    
    rc = engine.find('.//RUNNINGCONFIG')
    if rc is None: continue
    lines = rc.findall('LINE')
    
    # Print lines with numbers to see exactly what's there
    for i, l in enumerate(lines):
        text = l.text or ''
        print(f"{i+1:3d}: {text}")
