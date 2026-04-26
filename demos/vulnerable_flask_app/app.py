"""
Intentionally vulnerable Flask application for WRAITH demo purposes.

⚠️  THIS APP IS INTENTIONALLY VULNERABLE — DO NOT DEPLOY IN PRODUCTION.
It contains real security flaws for testing WRAITH's detection capabilities.
"""

import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
SECRET_KEY = "super_secret_key_12345"  # CWE-798: Hardcoded secret
app.secret_key = SECRET_KEY


def get_db():
    conn = sqlite3.connect("demo.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT
        )
    """)
    # Seed data
    try:
        conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin')")
        conn.execute("INSERT INTO users VALUES (2, 'user', 'password', 'user')")
        conn.execute("INSERT INTO notes VALUES (1, 1, 'Admin secret note')")
        conn.execute("INSERT INTO notes VALUES (2, 2, 'User public note')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    return conn


# ── SQL Injection (CWE-89) ─────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # VULNERABLE: String formatting in SQL query
    cursor = db.execute(
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    )
    user = cursor.fetchone()
    if user:
        return jsonify({"status": "ok", "user": user[1], "role": user[3]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ── IDOR (CWE-639) ─────────────────────────────────────────────────────
@app.route("/notes/<int:note_id>")
def get_note(note_id):
    db = get_db()
    # VULNERABLE: No authorisation check — any user can read any note
    cursor = db.execute(f"SELECT * FROM notes WHERE id={note_id}")
    note = cursor.fetchone()
    if note:
        return jsonify({"id": note[0], "user_id": note[1], "content": note[2]})
    return jsonify({"error": "Not found"}), 404


# ── Command Injection (CWE-78) ─────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: Unsanitised user input in shell command
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})


# ── SSTI (CWE-1336) ────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULNERABLE: User input rendered directly in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# ── Insecure Deserialization (CWE-502) ─────────────────────────────────
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # VULNERABLE: Unpickling untrusted data
    obj = pickle.loads(data)
    return jsonify({"loaded": str(obj)})


# ── Path Traversal (CWE-22) ────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # VULNERABLE: No path sanitisation
    try:
        with open(f"./files/{filename}") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404


# ── Open Redirect (CWE-601) ────────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # VULNERABLE: Unvalidated redirect
    from flask import redirect
    return redirect(url)


# ── Missing Security Headers ───────────────────────────────────────────
# No CSP, no HSTS, no X-Frame-Options — intentionally missing


# ── LLM Endpoint (for LLM red team testing) ────────────────────────────
@app.route("/api/chat", methods=["POST"])
def chat():
    """Simulated LLM endpoint for red team testing."""
    data = request.get_json(force=True)
    user_msg = data.get("message", data.get("prompt", data.get("input", "")))

    # VULNERABLE: No input sanitisation, system prompt leakable
    system_prompt = "You are a helpful assistant. Internal API key: sk-demo-12345"

    # Simulate basic LLM response (for demo without real LLM)
    if "system prompt" in user_msg.lower() or "instructions" in user_msg.lower():
        # Simulates prompt injection success
        response = f"My system prompt is: {system_prompt}"
    elif "ignore" in user_msg.lower() and "previous" in user_msg.lower():
        response = "PWNED — I have been jailbroken!"
    else:
        response = f"I received your message: {user_msg[:100]}"

    return jsonify({"response": response})


if __name__ == "__main__":
    os.makedirs("files", exist_ok=True)
    with open("files/readme.txt", "w") as f:
        f.write("Welcome to the demo app!")
    app.run(host="0.0.0.0", port=5001, debug=True)
