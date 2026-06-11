import shelve, os, sys
db_path = os.path.join(os.path.dirname(__file__), 'sessions', 'sessions_db')
with shelve.open(db_path) as db:
    for sid, session in db.items():
        if 'ai_solution' in session:
            sol = session['ai_solution']
            if not sol: continue
            devices = sol.get('devices', {})
            print(f"\n=== Session {sid} ===")
            for dev, cfg in devices.items():
                cmds = cfg.get('commands', [])
                if dev.lower().replace('-', '').replace('_', '') == 'mlsd':
                    print(f"Device: {dev}")
                    for cmd in cmds[:10]:
                        print(f"  {cmd}")
                    if len(cmds) > 10:
                        print(f"  ... and {len(cmds)-10} more")
