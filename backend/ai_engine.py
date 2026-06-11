"""
ai_engine.py - Multi-provider AI engine for generating Cisco configurations

Supports:
- Google Gemini (free tier available)
- OpenAI (GPT-4o, GPT-4o-mini)
- Anthropic Claude (Sonnet, Haiku)
- Groq (Llama 3, free & fast)
- OpenRouter (100+ models)
- Ollama (local, fully offline)
"""

import json
import re


# ─── Provider Configurations ──────────────────────────────────────────────

PROVIDERS = {
    'gemini': {
        'name': 'Google Gemini',
        'models': ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-2.5-pro'],
        'requires_key': True,
        'free_tier': True,
    },
    'openai': {
        'name': 'OpenAI',
        'models': ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'o4-mini'],
        'requires_key': True,
        'free_tier': False,
    },
    'claude': {
        'name': 'Anthropic Claude',
        'models': ['claude-sonnet-4-20250514', 'claude-haiku-3'],
        'requires_key': True,
        'free_tier': False,
    },
    'groq': {
        'name': 'Groq',
        'models': ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'],
        'requires_key': True,
        'free_tier': True,
    },
    'deepseek': {
        'name': 'DeepSeek',
        'models': ['deepseek-reasoner', 'deepseek-chat'],
        'requires_key': True,
        'free_tier': True,
    },
    'nvidia': {
        'name': 'NVIDIA NIM',
        'models': ['meta/llama-3.3-70b-instruct', 'deepseek-ai/deepseek-r1'],
        'requires_key': True,
        'free_tier': True,
    },
    'openrouter': {
        'name': 'OpenRouter',
        'models': ['google/gemini-2.5-flash', 'anthropic/claude-sonnet-4', 'openai/gpt-4o', 'meta-llama/llama-3.3-70b-instruct'],
        'requires_key': True,
        'free_tier': False,
    },
    'ollama': {
        'name': 'Ollama (Local)',
        'models': ['llama3.1', 'mistral', 'codellama', 'qwen2.5'],
        'requires_key': False,
        'free_tier': True,
    },
}


def get_providers():
    """Return available AI providers and their models."""
    return PROVIDERS


# ─── System Prompt ────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are CiscoLabAI, an expert Cisco NetDevOps engineer acting as a Configuration Auditor.

YOUR ROLE: You analyze existing device configurations and lab instructions, then generate ONLY the MISSING commands needed to fulfill the lab requirements. You are an ADDITIVE tool — you complete what's missing, you never overwrite what exists.

CORE PRINCIPLES:

1. INSTRUCTION-DRIVEN ONLY:
   - Configure ONLY what the lab instructions explicitly ask for.
   - If the lab is about VLSM and static routing, do NOT add OSPF, STP priorities, HSRP, or VLANs unless the instructions specifically request them.
   - If the lab is about VLANs and trunking, do NOT add routing protocols unless the instructions say so.
   - NEVER invent features, protocols, or configurations that aren't requested.

2. PRESERVE EXISTING CONFIGURATIONS (IMMUTABLE):
   - Every IP address already configured is IMMUTABLE. Do NOT change it.
   - Every VLAN already created (with its name) is IMMUTABLE. Do NOT recreate or rename it.
   - Every OSPF process, router-id, and network statement already configured is IMMUTABLE.
   - Every EtherChannel/Port-channel already configured is IMMUTABLE.
   - Use existing Process IDs, VLAN IDs, and names exactly as they are.

3. ADDITIVE-ONLY COMMANDS:
   - Generate ONLY the commands that are MISSING from the current config.
   - Do NOT generate `no` commands unless you are explicitly fixing an error that prevents the lab goal.
   - `no shutdown` is always allowed and encouraged on interfaces that need to be active.
   - If an interface already has an IP, do NOT reconfigure it.

4. MANDATORY PC/SERVER IP ASSIGNMENT:
   - ALL PCs and Servers MUST receive proper IP configuration (ip_address, subnet_mask, default_gateway).
   - Use the pre-configured IP anchors and subnet information to mathematically deduce the correct IPs.
   - If instructions specify which address to assign (e.g., "first usable", "last usable"), follow them exactly.
   - If a PC/Server already has an IP configured, keep it unchanged.

5. SUBNET MATH & IP DEDUCTION:
   - Use pre-existing IPs as anchors to deduce the subnet bounds.
   - Example: If Router has 172.31.31.193/27, the subnet is 172.31.31.192/27 (range .193-.222), and you assign remaining IPs accordingly.
   - NEVER create IP conflicts — check all anchors before assigning.

6. IMPLICIT OPERATIONAL NECESSITIES:
   - If you configure an interface IP, always add `no shutdown`.
   - If instructions say a switch needs a management IP, use the correct SVI (e.g., `interface vlan 1` or the management VLAN SVI).
   - If instructions require end-to-end connectivity across multiple routers, you MUST configure routing on ALL intermediate routers (not just endpoints).

PROTOCOL-SPECIFIC RULES (apply ONLY when the instructions ask for these):

7. ETHERCHANNEL / PORT-CHANNEL:
   - Configure BOTH sides with matching mode (LACP: active/active, PAgP: desirable/desirable).
   - On 3560/3650: use `switchport trunk encapsulation dot1q` BEFORE `switchport mode trunk`.
   - Configure both the physical interfaces AND the Port-channel interface.

8. TRUNK NATIVE VLAN:
   - Native VLAN MUST be identical on BOTH ends of a trunk link.
   - If not specified in instructions, leave it as default (VLAN 1) on BOTH sides.

9. MULTILAYER SWITCH (L3):
   - Include `ip routing` for inter-VLAN routing.
   - Use `switchport trunk encapsulation dot1q` before trunk mode.
   - Create SVIs for each VLAN needing routing.

10. HSRP:
    - Configure on SVI interfaces of BOTH L3 switches.
    - Active router gets higher priority (150), standby gets default (100).
    - Include `standby X preempt`.
    - Virtual IP is what PCs use as gateway.

11. DHCP:
    - Always exclude infrastructure IPs (gateways, switches, servers).
    - Use `ip helper-address` on client VLANs if DHCP server is on another subnet.

12. INTERFACE NAMING:
    - Use EXACTLY the interface names from the topology data.
    - 2960: FastEthernet0/1, GigabitEthernet0/1
    - 3560/3650 MLS: GigabitEthernet1/0/1 (three-level)
    - Routers: GigabitEthernet0/0, Serial0/0/0
    - NEVER guess interface names.

OUTPUT FORMAT:
You MUST respond with valid JSON in this exact structure:
```json
{
  "devices": {
    "DeviceName1": {
      "type": "router|switch|pc|server",
      "commands": [
        "enable",
        "configure terminal",
        "hostname R1",
        "interface GigabitEthernet0/0",
        "ip address 192.168.1.1 255.255.255.0",
        "no shutdown",
        "exit",
        "end",
        "write memory"
      ]
    },
    "PC1": {
      "type": "pc",
      "ip_config": {
        "ip_address": "192.168.1.10",
        "subnet_mask": "255.255.255.0",
        "default_gateway": "192.168.1.1",
        "dns": "8.8.8.8"
      }
    }
  },
  "topology_changes": null,
  "explanation": "Brief summary of what was configured and why"
}
```

The lab instructions may be in French — understand and process them correctly.
If no topology changes are needed, set "topology_changes" to null.
If a device needs no changes, omit it from the "devices" object.
For each router/switch, provide the COMPLETE sequence including "enable", "configure terminal", and "end" / "write memory".
"""


def build_prompt(instructions, topology_data, mode='config_only', remarks='', audit_report=None):
    """
    Build the user prompt for the AI with all context about the lab.
    
    Args:
        instructions: Lab instructions text (may be in French)
        topology_data: Dict from topology_extractor.get_full_context()
        mode: 'full_auto' or 'config_only'
        remarks: Optional student notes/remarks to guide the AI
        audit_report: Optional dict from network_auditor.full_audit()
    """
    prompt_parts = []
    
    # ── Section 1: Mode ──
    prompt_parts.append("=== CISCO PACKET TRACER LAB TO SOLVE ===\n")
    
    if mode == 'config_only':
        prompt_parts.append("MODE: Config Only — Do NOT add/remove any devices or cables. Only configure existing devices.")
        prompt_parts.append("Set 'topology_changes' to null in your response.\n")
    else:
        prompt_parts.append("MODE: Full Auto — You may add devices, modules, and cables if the instructions require it.\n")
    
    # ── Section 2: Student Notes (highest priority) ──
    if remarks and remarks.strip():
        prompt_parts.append("=== STUDENT NOTES (HIGHEST PRIORITY) ===")
        prompt_parts.append("The student has provided specific directives. Follow these STRICTLY — they override general instructions:")
        prompt_parts.append(remarks.strip())
        prompt_parts.append("")
    
    # ── Section 3: Goal (Lab Instructions) ──
    prompt_parts.append("=== GOAL: LAB INSTRUCTIONS ===")
    prompt_parts.append("Configure ONLY what these instructions ask for. Do NOT add extra protocols or features.")
    if instructions:
        prompt_parts.append(instructions)
    else:
        prompt_parts.append("(No instructions found in the file. Configure devices based on the topology and workspace notes.)")
    prompt_parts.append("")
    
    # ── Section 4: Current State (Topology + Pseudo Running-Configs) ──
    prompt_parts.append("=== CURRENT STATE: NETWORK TOPOLOGY & DEVICE CONFIGURATIONS ===")
    prompt_parts.append(topology_data.get('topology_summary', 'No topology data available'))
    prompt_parts.append("")
    
    # ── Section 5: Network Audit Report (Python-verified facts) ──
    if audit_report:
        from network_auditor import build_audit_prompt_section
        audit_section = build_audit_prompt_section(audit_report)
        prompt_parts.append(audit_section)
        prompt_parts.append("")
    
    # ── Section 6: Constraints ──
    prompt_parts.append("\n=== CONSTRAINTS (CRITICAL — READ CAREFULLY) ===")
    prompt_parts.append("")
    prompt_parts.append("1. INSTRUCTION-DRIVEN ONLY: Configure ONLY what the lab instructions ask for.")
    prompt_parts.append("   Do NOT add OSPF, VLANs, STP, HSRP, NAT, ACLs, or any protocol unless the instructions explicitly request it.")
    prompt_parts.append("")
    prompt_parts.append("2. PRESERVE EXISTING: All pre-configured IPs, VLANs, OSPF processes, and EtherChannels are IMMUTABLE.")
    prompt_parts.append("   Use existing VLAN IDs/names. Use existing OSPF process IDs. Do NOT overwrite any existing IP address.")
    prompt_parts.append("")
    prompt_parts.append("3. ADDITIVE-ONLY: Generate only MISSING commands. No `no` commands except `no shutdown`.")
    prompt_parts.append("")
    prompt_parts.append("4. ALL PCs/Servers MUST get IP configuration (ip_address, subnet_mask, default_gateway).")
    prompt_parts.append("   Deduce correct IPs from subnet anchors and lab instructions.")
    prompt_parts.append("")
    prompt_parts.append("5. INTERFACE NAMES: Use EXACT names from the WIRING DIAGRAM above.")
    prompt_parts.append("   Example: If diagram shows 'MLS-D:GigabitEthernet1/0/1 <--> SW-A:GigabitEthernet0/1', use those exact names.")
    prompt_parts.append("")
    prompt_parts.append("6. DEVICE NAMES: Use EXACT names from the topology (e.g., 'SW_B' not 'SW-B').")
    prompt_parts.append("")
    prompt_parts.append("7. WORKSPACE NOTES: Check for floating text labels — instructors often hide IP addresses and subnet masks there.")
    prompt_parts.append("")
    prompt_parts.append("8. TWO-SIDED CONFIG: For EtherChannel, Trunk, and point-to-point links, configure BOTH ends.")
    prompt_parts.append("")
    prompt_parts.append("Respond with ONLY valid JSON in the specified format. No markdown, no code fences, no extra text.")
    
    return '\n'.join(prompt_parts)


# ─── AI Provider Implementations ─────────────────────────────────────────

def call_gemini(api_key, model, system_prompt, user_prompt):
    """Call Google Gemini API."""
    import google.generativeai as genai
    
    genai.configure(api_key=api_key)
    
    gen_model = genai.GenerativeModel(
        model_name=model,
        system_instruction=system_prompt
    )
    
    response = gen_model.generate_content(
        user_prompt,
        generation_config=genai.types.GenerationConfig(
            temperature=0.1,
            max_output_tokens=32768,
        )
    )
    
    return response.text


def call_openai(api_key, model, system_prompt, user_prompt, base_url=None):
    """Call OpenAI-compatible API (also used for Groq, OpenRouter)."""
    from openai import OpenAI
    
    client_kwargs = {'api_key': api_key}
    if base_url:
        client_kwargs['base_url'] = base_url
    
    client = OpenAI(**client_kwargs)
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.1,
        max_tokens=32768,
    )
    
    return response.choices[0].message.content


def call_claude(api_key, model, system_prompt, user_prompt):
    """Call Anthropic Claude API."""
    import anthropic
    
    client = anthropic.Anthropic(api_key=api_key)
    
    response = client.messages.create(
        model=model,
        max_tokens=16384,
        system=system_prompt,
        messages=[
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.1,
    )
    
    return response.content[0].text


def call_ollama(model, system_prompt, user_prompt, base_url='http://localhost:11434'):
    """Call local Ollama API."""
    import requests
    
    response = requests.post(
        f'{base_url}/api/generate',
        json={
            'model': model,
            'system': system_prompt,
            'prompt': user_prompt,
            'stream': False,
            'options': {
                'temperature': 0.1,
                'num_predict': 16384,
            }
        },
        timeout=300
    )
    response.raise_for_status()
    return response.json()['response']


def call_ai(provider, api_key, model, system_prompt, user_prompt):
    """
    Route to the appropriate AI provider.
    
    Args:
        provider: One of 'gemini', 'openai', 'claude', 'groq', 'openrouter', 'ollama'
        api_key: API key (empty string for Ollama)
        model: Model name
        system_prompt: System instructions
        user_prompt: User message with lab context
        
    Returns:
        str: Raw AI response text
    """
    if provider == 'gemini':
        return call_gemini(api_key, model, system_prompt, user_prompt)
    elif provider == 'openai':
        return call_openai(api_key, model, system_prompt, user_prompt)
    elif provider == 'claude':
        return call_claude(api_key, model, system_prompt, user_prompt)
    elif provider == 'groq':
        return call_openai(api_key, model, system_prompt, user_prompt,
                          base_url='https://api.groq.com/openai/v1')
    elif provider == 'openrouter':
        return call_openai(api_key, model, system_prompt, user_prompt,
                          base_url='https://openrouter.ai/api/v1')
    elif provider == 'deepseek':
        return call_openai(api_key, model, system_prompt, user_prompt,
                          base_url='https://api.deepseek.com')
    elif provider == 'nvidia':
        return call_openai(api_key, model, system_prompt, user_prompt,
                          base_url='https://integrate.api.nvidia.com/v1')
    elif provider == 'ollama':
        return call_ollama(model, system_prompt, user_prompt)
    else:
        raise ValueError(f"Unknown AI provider: {provider}")


def parse_ai_response(response_text):
    """
    Parse the AI response to extract structured configuration data.
    Handles truncated JSON, markdown fences, and other common AI output quirks.
    """
    text = response_text.strip()
    
    # Remove markdown code fences aggressively
    # Handle ```json ... ``` , ``` ... ```, and variations
    if '```' in text:
        # Find the first { after any opening fence
        fence_start = text.find('```')
        next_newline = text.find('\n', fence_start)
        if next_newline != -1:
            text = text[next_newline + 1:]
        # Remove trailing fence
        last_fence = text.rfind('```')
        if last_fence != -1:
            text = text[:last_fence]
    
    text = text.strip()
    
    # Try direct parse first
    try:
        result = json.loads(text)
        if 'devices' in result:
            return result
    except json.JSONDecodeError:
        pass
    
    # Try to extract the outermost JSON object
    first_brace = text.find('{')
    if first_brace == -1:
        return {
            'error': 'No JSON object found in AI response',
            'devices': {},
            'topology_changes': None,
        }
    
    text = text[first_brace:]
    
    # Try parsing as-is
    try:
        result = json.loads(text)
        if 'devices' in result:
            return result
    except json.JSONDecodeError:
        pass
    
    # JSON is likely truncated. Try to repair it by closing open structures.
    repaired = _repair_truncated_json(text)
    if repaired:
        try:
            result = json.loads(repaired)
            if 'devices' in result:
                print(f"[~] Repaired truncated JSON successfully")
                return result
        except json.JSONDecodeError:
            pass
    
    # Last resort: try to find the last complete device entry
    # and build a valid JSON from what we have
    partial = _extract_partial_devices(text)
    if partial:
        return partial
    
    return {
        'error': 'Failed to parse AI response (truncated or invalid JSON)',
        'devices': {},
        'topology_changes': None,
    }


def _repair_truncated_json(text):
    """Try to repair truncated JSON by closing open brackets and braces."""
    # Track what's open
    stack = []
    in_string = False
    escape_next = False
    
    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in '{[':
            stack.append(ch)
        elif ch == '}':
            if stack and stack[-1] == '{':
                stack.pop()
        elif ch == ']':
            if stack and stack[-1] == '[':
                stack.pop()
    
    # If we're inside a string, close it
    if in_string:
        text += '"'
    
    # Close any remaining open structures
    closers = {'[': ']', '{': '}'}
    for opener in reversed(stack):
        text += closers.get(opener, '')
    
    return text


def _extract_partial_devices(text):
    """Extract whatever complete device entries we can find from partial JSON."""
    devices = {}
    
    # Find all "DeviceName": { ... } patterns
    # Match device entries that have a complete commands array
    device_pattern = re.compile(
        r'"([^"]+)"\s*:\s*\{[^{}]*"type"\s*:\s*"([^"]+)"[^{}]*"commands"\s*:\s*\[((?:[^[\]]*|\[(?:[^[\]]*|\[[^[\]]*\])*\])*)\][^{}]*\}',
        re.DOTALL
    )
    
    for match in device_pattern.finditer(text):
        name = match.group(1)
        dtype = match.group(2)
        cmds_raw = match.group(3)
        
        # Parse the commands array
        cmds = re.findall(r'"((?:[^"\\]|\\.)*)"', cmds_raw)
        if cmds:
            devices[name] = {
                'type': dtype,
                'commands': cmds,
            }
    
    # Also find PC/Server ip_config entries 
    ip_pattern = re.compile(
        r'"([^"]+)"\s*:\s*\{[^{}]*"type"\s*:\s*"(pc|server)"[^{}]*"ip_config"\s*:\s*\{([^{}]*)\}[^{}]*\}',
        re.DOTALL | re.IGNORECASE
    )
    
    for match in ip_pattern.finditer(text):
        name = match.group(1)
        dtype = match.group(2)
        ip_raw = match.group(3)
        
        ip_config = {}
        for field in ['ip', 'mask', 'gateway', 'dns']:
            m = re.search(rf'"{field}"\s*:\s*"([^"]*)"', ip_raw)
            if m:
                ip_config[field] = m.group(1)
        
        if ip_config:
            devices[name] = {
                'type': dtype,
                'ip_config': ip_config,
            }
    
    if devices:
        # Try to extract explanation
        expl_match = re.search(r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
        explanation = expl_match.group(1) if expl_match else ''
        
        return {
            'devices': devices,
            'topology_changes': None,
            'explanation': explanation,
        }
    
    return None


def solve_lab(provider, api_key, model, instructions, topology_data, mode='full_auto'):
    """
    Main entry point: Send lab to AI and get structured solution.
    
    Args:
        provider: AI provider name
        api_key: API key
        model: Model name
        instructions: Lab instructions text
        topology_data: Full context dict from topology_extractor
        mode: 'full_auto' or 'config_only'
        
    Returns:
        dict: Parsed solution with device configs and topology changes
    """
    user_prompt = build_prompt(instructions, topology_data, mode)
    
    raw_response = call_ai(provider, api_key, model, SYSTEM_PROMPT, user_prompt)
    
    parsed = parse_ai_response(raw_response)
    parsed['raw_response'] = raw_response
    
    return parsed
