from flask import Flask, render_template, request, redirect, url_for, send_file
import sqlite3, os
from datetime import datetime

app = Flask(__name__)
DB = "logs/attacks.db"
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

def log_attack(attack_type, ip, username=None, password=None, filename=None, endpoint=None, user_agent=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO attacks (attack_type, ip, username, password, filename, endpoint, user_agent, timestamp) VALUES (?,?,?,?,?,?,?,?)",
              (attack_type, ip, username, password, filename, endpoint, user_agent, ts))
    conn.commit()
    conn.close()

@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "-")
    log_attack("login_attempt", ip, username, password, None, "/login", ua)
    return "Invalid credentials", 401

@app.route("/upload", methods=["GET","POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            return "No file", 400
        filename = f.filename or "unnamed"
        safe_path = os.path.join(UPLOAD_DIR, filename)
        f.save(safe_path)
        ip = request.remote_addr or "unknown"
        ua = request.headers.get("User-Agent", "-")
        log_attack("file_upload", ip, None, None, filename, "/upload", ua)
        return "Upload received. Admin will review.", 201
    return render_template("upload.html")

@app.route("/admin")
@app.route("/admin/<path:subpath>")
def admin_probe(subpath=None):
    path = "/admin" + ("/"+subpath if subpath else "")
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "-")
    log_attack("admin_probe", ip, None, None, None, path, ua)
    return render_template("admin_probe.html", path=path), 403
@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT id, attack_type, ip, username, password, filename, endpoint, user_agent, timestamp FROM attacks ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("dashboard.html", attacks=rows)

@app.route("/export")
def export_csv():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM attacks ORDER BY id DESC").fetchall()
    conn.close()
    csv_path = "logs/attacks_export.csv"
    with open(csv_path, "w") as f:
        f.write("id,attack_type,ip,username,password,filename,endpoint,user_agent,timestamp\n")
        for r in rows:
            line = ",".join(['"{}"'.format(str(x).replace('"','""')) for x in r])
            f.write(line + "\n")
    return send_file(csv_path, as_attachment=True)
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
