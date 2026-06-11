# CiscoLabAI

A small web app that takes a Cisco Packet Tracer lab file (`.pka` / `.pkt`), figures out
what configuration is missing, asks an LLM to write the missing Cisco IOS commands, checks
that output with plain Python before trusting it, and hands you back a solved file you can
open straight in Packet Tracer.

I started this because grading and solving these labs by hand is tedious, and because the
`.pka` format is an encrypted binary blob that no tool I could find would open. Most of the
work here is actually getting *into* the file format; the LLM part is the easy bit.

## How it works

The pipeline is five stages. Bytes go in one end and come out the other:

```
.pka bytes  →  XML  →  context dict  →  LLM JSON  →  patched XML  →  .pka bytes
```

1. **Decrypt / encrypt** (`pka_parser.py`) — Packet Tracer uses two schemes. Older files
   (PT7) are just XOR + zlib. Newer ones (PT8) are XOR → Twofish-EAX → XOR → zlib. The
   Twofish-EAX layer (CMAC + CTR) is implemented by hand. Files always get re-encrypted in
   the same scheme they arrived in.
2. **Extract topology** (`topology_extractor.py`) — turns the XML into a plain dict of
   devices, interfaces and links, and rebuilds a `show running-config`-style text per
   device. LLMs reason about that text far better than they do about raw XML.
3. **Audit** (`network_auditor.py`) — a deterministic "digital twin". Python does the subnet
   math, VLAN membership and OSPF process IDs, not the model. Whatever the audit proves true
   gets fed to the LLM as fixed facts it isn't allowed to argue with.
4. **Ask the model** (`ai_engine.py`) — works with Gemini, OpenAI, Claude, Groq, OpenRouter,
   DeepSeek, NVIDIA and local Ollama. The contract is strictly *additive*: it may only add
   the commands the instructions ask for and must treat existing IPs/VLANs/OSPF as
   untouchable. Lab instructions are often in French, which is handled.
5. **Merge back** (`config_injector.py`) — a guardrail layer filters out anything
   destructive or hallucinated (no deleting existing VLANs, no overwriting set IPs, no
   duplicate OSPF processes) before splicing the surviving commands back into the file.

On top of that there's a verification oracle (`oracle.py`) that doesn't need an answer key:
a small control-plane simulator proves host-to-host reachability, an invariants checker
catches protocol mistakes (duplicate IPs, trunk mismatches, EtherChannel problems, etc.),
and an objectives parser pulls the actual success criteria out of the instruction text and
tests them. A closed-loop solver (`solver.py`) uses that oracle as a reward signal: solve,
verify, feed the failures back, solve again, keep the best result.

## Running it

You'll need Python 3.12.

```powershell
cd backend
pip install -r requirements.txt
python app.py
```

That serves both the API and the frontend at http://localhost:5000. Upload a `.pka`, pick a
provider, solve, and download.

### One annoying dependency

The `.pka` decryption needs `twofish`, which is **not** in `requirements.txt` and has to be
installed on its own:

```powershell
pip install twofish
```

On Python 3.12 the published `twofish` package breaks because it imports the removed `imp`
module. Run `python patch_twofish.py` once to fix the installed copy (it rewrites the loader
to find the `.pyd` with `glob` instead). The path in that script is hardcoded to my machine,
so adjust it if your Python lives elsewhere.

## Layout

```
backend/    Flask API + the whole pipeline (one module per stage)
frontend/   Plain HTML/CSS/JS, no build step, uses vis-network for the topology view
```

The frontend is deliberately a single static page talking to the API on the same origin —
no framework, no bundler, nothing to compile.

## Status

Works on the real exam labs I've thrown at it. Still rough in places, and the format
handling has only been tested against the Packet Tracer versions I have on hand. PRs and bug
reports welcome.
