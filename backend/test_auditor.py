"""Test the network auditor against the real exam PKA."""
import sys, os, json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(__file__))
from pka_parser import decode_pka
from topology_extractor import get_full_context
from network_auditor import full_audit, build_audit_prompt_section

uploads = 'uploads'
files = sorted([f for f in os.listdir(uploads) if f.endswith('.pka')],
               key=lambda x: os.path.getmtime(os.path.join(uploads, x)), reverse=True)
pka_path = os.path.join(uploads, files[0])
print(f"Testing against: {pka_path}\n")

xml_string = decode_pka(pka_path)
context = get_full_context(xml_string)
audit = full_audit(context)

print(build_audit_prompt_section(audit))
print("\n=== RAW IP ANCHORS ===")
for net, info in audit['ip_anchors'].items():
    print(f"  {net}: gateway={info['gateway']}")
    for m in info['members']:
        print(f"    {m['device']}:{m['interface']} = {m['ip']}")
