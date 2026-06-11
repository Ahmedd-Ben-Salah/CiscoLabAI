"""
app.py - Flask backend API for CiscoLabAI

Provides REST API endpoints for:
- File upload and parsing
- AI-powered lab solving
- Config injection and file download
"""

import os
import json
import uuid
import shelve
import tempfile
import traceback
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS

from pka_parser import decode_pka_bytes, encode_pka_bytes
from topology_extractor import parse_xml, get_full_context
from ai_engine import get_providers, solve_lab, SYSTEM_PROMPT, build_prompt, call_ai, parse_ai_response
from config_injector import inject_all_configs
from topology_modifier import apply_topology_changes
from network_auditor import full_audit

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable static file caching
CORS(app)

@app.after_request
def add_no_cache_headers(response):
    """Prevent browser from caching static files (JS, CSS, HTML)."""
    if 'text/html' in response.content_type or \
       'javascript' in response.content_type or \
       'text/css' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Disk-backed session storage (survives server restarts/reloads)
SESSION_DIR = os.path.join(os.path.dirname(__file__), 'sessions')
os.makedirs(SESSION_DIR, exist_ok=True)
SESSION_DB_PATH = os.path.join(SESSION_DIR, 'sessions_db')

def get_session(session_id):
    """Retrieve a session from disk."""
    try:
        with shelve.open(SESSION_DB_PATH) as db:
            return db.get(session_id)
    except Exception:
        return None

def set_session(session_id, data):
    """Store a session to disk."""
    with shelve.open(SESSION_DB_PATH) as db:
        db[session_id] = data

def has_session(session_id):
    """Check if a session exists."""
    try:
        with shelve.open(SESSION_DB_PATH) as db:
            return session_id in db
    except Exception:
        return False

# ─── Serve Frontend ───────────────────────────────────────────────────────

@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../frontend', path)

# ─── API Routes ───────────────────────────────────────────────────────────

@app.route('/api/providers', methods=['GET'])
def api_get_providers():
    """Return available AI providers and their models."""
    return jsonify(get_providers())


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """
    Upload a .pka/.pkt file and parse it.
    
    Returns topology data, instructions, and a session ID for further operations.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.pka', '.pkt']:
        return jsonify({'error': 'Invalid file type. Please upload a .pka or .pkt file'}), 400
    
    try:
        # Read file bytes
        file_bytes = file.read()
        
        # Decode the PKA/PKT file to XML
        xml_string = decode_pka_bytes(file_bytes)
        
        # Extract full context
        context = get_full_context(xml_string)
        
        # Run network audit (Python-verified validation)
        audit_report = full_audit(context)
        
        # Generate session ID
        session_id = str(uuid.uuid4())[:8]
        
        # Store in session (disk-backed)
        set_session(session_id, {
            'filename': file.filename,
            'extension': ext,
            'xml_string': xml_string,
            'context': context,
            'audit_report': audit_report,
            'ai_solution': None,
            'original_bytes': file_bytes,
        })
        
        # Return parsed data (without full XML or configs to keep response small)
        response_data = {
            'session_id': session_id,
            'filename': file.filename,
            'version': context['version'],
            'device_count': context['device_count'],
            'connection_count': context['connection_count'],
            'instructions': context['instructions'],
            'devices': [{
                'name': d['name'],
                'type': d['type'],
                'model': d['model'],
                'category': d['category'],
                'x': d.get('x', 0),
                'y': d.get('y', 0),
                'interfaces': d.get('interfaces', []),
                'has_config': bool(d.get('running_config') and len(d.get('running_config', '')) > 10),
            } for d in context['devices']],
            'connections': context['connections'],
            'audit_summary': audit_report.get('summary', {}),
        }
        
        return jsonify(response_data)
    
    except ValueError as e:
        return jsonify({'error': f'Failed to parse file: {str(e)}'}), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/api/audit', methods=['POST'])
def api_audit():
    """Return the full network audit report for a session."""
    data = request.json
    session_id = data.get('session_id') if data else None
    
    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400
    
    session = get_session(session_id)
    audit_report = session.get('audit_report', {})
    
    return jsonify({
        'success': True,
        'audit': audit_report,
    })


@app.route('/api/verify', methods=['POST'])
def api_verify():
    """
    Run the answer-key-independent connectivity oracle on the current (or
    most recently applied) network state for a session.

    Returns endpoint config-completeness, host-to-host reachability (forward +
    return path), and gateway sanity — all derived deterministically, no AI.
    """
    data = request.json
    session_id = data.get('session_id') if data else None

    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400

    session = get_session(session_id)

    try:
        from oracle import verify
        # Prefer the modified network if a solution was applied, else the original.
        if session.get('modified_xml'):
            context = get_full_context(session['modified_xml'])
        else:
            context = session['context']
        report = verify(context)
        return jsonify({'success': True, 'report': report})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Verification failed: {str(e)}'}), 500


@app.route('/api/solve', methods=['POST'])
def api_solve():
    """
    Send the lab to the AI for solving.
    
    Expects JSON body:
    {
        "session_id": "abc12345",
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key": "your-api-key",
        "mode": "full_auto" | "config_only"
    }
    """
    data = request.json
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    session_id = data.get('session_id')
    provider = data.get('provider')
    model = data.get('model')
    api_key = data.get('api_key', '')
    mode = data.get('mode', 'config_only')
    remarks = data.get('remarks', '')
    
    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400
    
    if not provider:
        return jsonify({'error': 'No AI provider specified'}), 400
    
    if not model:
        return jsonify({'error': 'No model specified'}), 400
    
    session = get_session(session_id)
    context = session['context']
    
    try:
        # Build prompt and call AI (with audit report for structured context)
        audit_report = session.get('audit_report')
        user_prompt = build_prompt(context['instructions'], context, mode, remarks, audit_report=audit_report)
        
        raw_response = call_ai(provider, api_key, model, SYSTEM_PROMPT, user_prompt)
        
        # Parse AI response
        solution = parse_ai_response(raw_response)
        solution['raw_response'] = raw_response
        
        # Store solution in session
        session['ai_solution'] = solution
        set_session(session_id, session)
        
        # Build response with per-device configs
        device_configs = {}
        for dev_name, dev_config in solution.get('devices', {}).items():
            device_configs[dev_name] = {
                'type': dev_config.get('type', 'unknown'),
                'commands': dev_config.get('commands', []),
                'ip_config': dev_config.get('ip_config'),
            }
        
        response = {
            'success': True,
            'device_configs': device_configs,
            'topology_changes': solution.get('topology_changes'),
            'explanation': solution.get('explanation', ''),
            'error': solution.get('error'),
        }
        
        return jsonify(response)
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'AI call failed: {str(e)}',
        }), 500


@app.route('/api/solve_auto', methods=['POST'])
def api_solve_auto():
    """
    Closed-loop solve: generate config, apply, verify, feed failures back, repeat.

    Stores the best verified result (modified XML + re-encoded bytes) so the file
    is immediately downloadable, and returns the per-iteration history + final
    verification report.
    """
    data = request.json or {}
    session_id = data.get('session_id')
    provider = data.get('provider')
    model = data.get('model')
    api_key = data.get('api_key', '')
    mode = data.get('mode', 'config_only')
    remarks = data.get('remarks', '')
    max_iters = int(data.get('max_iterations', 3))

    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400
    if not provider or not model:
        return jsonify({'error': 'Provider and model are required'}), 400

    session = get_session(session_id)

    try:
        from solver import solve_with_refinement
        from pka_parser import _decrypt_stage1, is_old_pt

        best = solve_with_refinement(
            provider, api_key, model,
            session['xml_string'], session['context'], session.get('audit_report'),
            mode=mode, remarks=remarks, max_iters=max_iters)

        # Re-encode the best network in the original PKA format.
        stage1 = _decrypt_stage1(session['original_bytes'])
        use_pt8 = not is_old_pt(stage1)
        modified_bytes = encode_pka_bytes(best['modified_xml'], force_pt8=use_pt8)

        session['modified_xml'] = best['modified_xml']
        session['modified_bytes'] = modified_bytes
        session['ai_solution'] = {'devices': best['device_view']}
        set_session(session_id, session)

        # Per-device config for the UI.
        device_configs = {n: {'type': c.get('type', 'unknown'),
                              'commands': c.get('commands', []),
                              'ip_config': c.get('ip_config')}
                          for n, c in best['device_view'].items()}

        return jsonify({
            'success': True,
            'iterations': best['history'],
            'best_iteration': best['iteration'],
            'verdict': best['report']['verdict'],
            'report': best['report'],
            'device_configs': device_configs,
            'config_results': best['config_results'],
            'file_size': len(modified_bytes),
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Auto-solve failed: {str(e)}'}), 500


@app.route('/api/apply', methods=['POST'])
def api_apply():
    """
    Apply the AI solution to the PKA file and prepare it for download.
    
    Uses string-based replacements on the original XML to preserve
    the exact formatting Packet Tracer expects.
    """
    data = request.json
    session_id = data.get('session_id') if data else None
    
    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400
    
    session = get_session(session_id)
    
    if not session.get('ai_solution'):
        return jsonify({'error': 'No AI solution to apply. Run /api/solve first.'}), 400
    
    try:
        from config_injector import apply_solution_to_xml

        modified_xml, config_results = apply_solution_to_xml(
            session['xml_string'],
            session['ai_solution'],
            session['context']['devices'],
            session.get('audit_report'),
        )

        # Detect original format (PT8 vs old) and re-encode accordingly
        original_bytes = session['original_bytes']
        from pka_parser import _decrypt_stage1, is_old_pt
        stage1 = _decrypt_stage1(original_bytes)
        use_pt8 = not is_old_pt(stage1)
        
        # Encode back to PKA/PKT format using the SAME format as the original
        modified_bytes = encode_pka_bytes(modified_xml, force_pt8=use_pt8)
        
        # Store the modified file
        session['modified_bytes'] = modified_bytes
        session['modified_xml'] = modified_xml
        set_session(session_id, session)
        
        return jsonify({
            'success': True,
            'topology_results': {},
            'config_results': config_results,
            'file_size': len(modified_bytes),
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Failed to apply solution: {str(e)}',
        }), 500


@app.route('/api/download', methods=['GET'])
@app.route('/api/download/<path:requested_filename>', methods=['GET'])
def api_download(requested_filename=None):
    """Download the modified PKA/PKT file."""
    session_id = request.args.get('session_id')
    
    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid or expired session ID'}), 400
    
    session = get_session(session_id)
    
    if not session.get('modified_bytes'):
        return jsonify({'error': 'No modified file available. Run /api/apply first.'}), 400
    
    # Create temp file for download
    filename = session['filename']
    name, ext = os.path.splitext(filename)
    download_name = f"{name}_solved{ext}"
    print(f"\n==========================================")
    print(f"DOWNLOAD REQUESTED: original_filename='{filename}' -> download_name='{download_name}'")
    print(f"==========================================\n")
    
    # Write to temp file
    temp_dir = os.path.join(os.path.dirname(__file__), 'uploads')
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, download_name)
    
    with open(temp_path, 'wb') as f:
        f.write(session['modified_bytes'])
    
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=download_name,
        mimetype='application/octet-stream'
    )


@app.route('/api/device/<device_name>/config', methods=['GET'])
def api_device_config(device_name):
    """Get the current running-config of a specific device."""
    session_id = request.args.get('session_id')
    
    if not session_id or not has_session(session_id):
        return jsonify({'error': 'Invalid session'}), 400
    
    session = get_session(session_id)
    
    for device in session['context']['devices']:
        if device['name'].lower() == device_name.lower():
            return jsonify({
                'name': device['name'],
                'type': device['type'],
                'model': device['model'],
                'running_config': device.get('running_config', ''),
                'interfaces': device.get('interfaces', []),
            })
    
    return jsonify({'error': f'Device not found: {device_name}'}), 404


# ─── Main ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  CiscoLabAI — AI-Powered Packet Tracer Lab Solver")
    print("  http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=True, reloader_type='stat')
