from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
import os
import hashlib

app = Flask(__name__)
# 🔑 Real secret — but not used in auth (decoy for source leak)
app.secret_key = "chronos_dev_2025"

# 🚩 FLAG 1: Hidden in config — but exposed via debug endpoint keys
app.config['INTERNAL_FLAG'] = "CUET{fl4sk_c0nfig_l3ak_1s_r3al}"

# Hardcoded valid credentials — no DB, no query
VALID_USERNAME = "admin"
VALID_PASSWORD = "3iRIy4nI"  # exact match required

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
  <title>Project Chronos — Dev Portal</title>
  <style>
    body { background:#0d0d0d; color:#0f0; font-family: monospace; padding:2em; }
    .card { max-width:400px; margin:2em auto; border:1px solid #0a0; padding:1.5em; }
    input, button { width:100%; padding:0.6em; margin:0.4em 0; background:#1a1a1a; color:#0f0; border:1px solid #0a0; }
    button:hover { background:#0a0; }
  </style>
</head>
<body>
  <h1>🕒 Project Chronos — Dev Portal (v2.1)</h1>
  <div class="card">
    <h3>🔐 Developer Login</h3>
    <form method="POST" action="/auth">
      <input type="text" name="user" placeholder="Username" autocomplete="off">
      <input type="password" name="pass" placeholder="Password" autocomplete="off">
      <button type="submit">→ Submit</button>
    </form>
    <p style="font-size:0.8em; color:#555; margin-top:1em;">
      <!--html_c0mm3nt5_1n_t3mpl4t3s_s0m3tim3s_ar3_r3al-->
      Note: Use internal test creds. Check /dev/paths for debug tools.
    </p>
  </div>
</body>
</html>
    ''')

# ✅ Exact credential check — no SQL, no hashing, no coercion
@app.route('/auth', methods=['POST'])
def authenticate():
    user = request.form.get('user', '')
    pwd = request.form.get('pass', '')

    # 🔑 Strict string match — no tricks, no SQL
    if user == VALID_USERNAME and pwd == VALID_PASSWORD:
        session['logged_in'] = True
        session['role'] = 'developer'  # ❗ Key for next stage
        return redirect('/console')
    
    return "❌ Access denied. Check credentials.", 403

@app.route('/console')
def console():
    if not session.get('logged_in'):
        return redirect('/')

    role = session.get('role', 'guest')
    
    # 💡 Inner code hint: reveals hidden path only if role == 'developer'
    inner_hint = ""
    if role == "developer":
        inner_hint = '''
        <div style="background:#1a1a00; border:1px dashed #aa0; padding:1em; margin:1em 0;">
          <code>// dev/internal/portal</code> — requires <code>role = "engineer"</code><br>
          <em>Tip: The console trusts upstream headers. Maybe a proxy can help? You may try putting this: K-Hfre-Ebyr: ratvarre out below cookie session.</em>
          <em>This may help you to decrypti this: "Uk9UMTM="</em>
        </div>
        '''

    return render_template_string(f'''
<!DOCTYPE html>
<html>
<head><title>Dev Console</title></head>
<body style="background:#0d0d0d; color:#0f0; font-family:monospace; padding:2em">
  <h2>💻 Developer Console</h2>
  <p>Status: <span style="color:#0a0;">Authenticated</span> | Role: <code>{role}</code></p>
  <ul>
    <li><a href="/debug/config">⚙️ Config Snapshot</a></li>
    <li><a href="/source">📄 Source (sanitized)</a></li>
    <li><a href="/dev/internal/portal" style="color:#a55;">[ACCESS RESTRICTED]</a></li>
  </ul>
  {inner_hint}
</body>
</html>
    ''')

# 🔍 Safe-ish config leak: only keys (but INTERNAL_FLAG visible)
@app.route('/debug/config')
def config_debug():
    if not session.get('logged_in'):
        return "🔒 Unauthorized", 401
    return jsonify({
        "mode": "dev",
        "config_keys": [k for k in app.config.keys() if k != 'SECRET_KEY']
        # NOTE: Is_Internal_Flag_There???
    })

# 📜 Source leak — redacts secret_key line, but NOT the config flag line
@app.route('/source')
def source_leak():
    if not session.get('logged_in'):
        return "🔒 Unauthorized", 401

    with open(__file__, 'r') as f:
        lines = f.readlines()

    output = []
    for line in lines:
        # Only redact the secret_key assignment line (by exact pattern)
        if 'app.secret_key =' in line:
            output.append("# [REDACTED: secret key line]\n")
        else:
            output.append(line)

    return "<pre style='color:#0f0; background:#000; padding:1em;'>" + "".join(output) + "</pre>"

# 🚪 Hidden path: requires role = "engineer" (not set by login)
@app.route('/dev/internal/portal')
def internal_portal():
    # 🔑 Server-side check — must be changed via Burp (e.g., add X-Role: engineer header or tamper session)
    role = session.get('role')
    
    # ✨ New: Allow escalation via **request header** (realistic microservice trust)
    # Simulates: reverse proxy sets X-User-Role → app trusts it
    if request.headers.get('X-User-Role') == 'engineer':
        role = 'engineer'

    if role != 'engineer':
        return '''
        <h3>⚠️ Role Mismatch</h3>
        <p>Current role: <code>{}</code></p>
        <p>Required: <code>engineer</code></p>
        <p><em>Hint: Some gateways inject role headers. Try intercepting the request.</em></p>
        '''.format(role), 403

    # 🚩 Final flag — revealed only after Burp manipulation
    return render_template_string('''
<!DOCTYPE html>
<html>
<head><title>Engineer Portal — UNLOCKED</title></head>
<body style="background:#001a00; color:#0f0; font-family:monospace; padding:2em">
  <h2>✅ Access Level: ENGINEER</h2>
  <p>You've successfully escalated privileges via header injection.</p>
  <hr>
  <h3>🎯 Flag:</h3>
  <code>CUET{burp_header_inject1on_1s_real}</code>
  <hr>
  <small><em>Audit log: Role escalated via X-User-Role header. (Never trust client-side roles!)</em></small>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)