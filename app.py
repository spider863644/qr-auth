import os
import io
import base64
import uuid
import sqlite3
import random
from datetime import datetime
from functools import wraps

import pandas as pd
import qrcode
from flask import (
    Flask, request, redirect, url_for, session, g,
    render_template_string, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# =========================================================
# CONFIG
# =========================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-now")
DB_NAME = os.environ.get("DB_NAME", "auth_flask.db")

# =========================================================
# DATABASE
# =========================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column(table_name, column_name, column_def):
    db = get_db()
    cur = db.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cur.fetchall()]
    if column_name not in columns:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")
        db.commit()


def init_db():
    db = get_db()

    db.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT,
        trusted INTEGER DEFAULT 1,
        created_at TEXT
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS login_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_token TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        requester_device_id TEXT NOT NULL,
        status TEXT NOT NULL,
        risk_result TEXT,
        login_hour INTEGER,
        failed_attempts INTEGER,
        new_device INTEGER,
        distance_km REAL,
        trusted_device INTEGER,
        created_at TEXT
    )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_hour INTEGER,
        failed_attempts INTEGER,
        new_device INTEGER,
        distance_km REAL,
        trusted_device INTEGER,
        risk_result TEXT,
        timestamp TEXT
    )
    """)

    db.commit()

    ensure_column("users", "created_at", "TEXT")
    ensure_column("devices", "created_at", "TEXT")
    ensure_column("login_requests", "risk_result", "TEXT")
    ensure_column("login_requests", "login_hour", "INTEGER")
    ensure_column("login_requests", "failed_attempts", "INTEGER")
    ensure_column("login_requests", "new_device", "INTEGER")
    ensure_column("login_requests", "distance_km", "REAL")
    ensure_column("login_requests", "trusted_device", "INTEGER")


with app.app_context():
    init_db()

# =========================================================
# MACHINE LEARNING
# =========================================================
def train_model():
    data = []
    labels = []

    for _ in range(1500):
        login_hour = random.randint(0, 23)
        failed_attempts = random.randint(0, 6)
        new_device = random.randint(0, 1)
        distance_km = random.uniform(0, 5000)
        trusted_device = random.randint(0, 1)

        score = 0
        if login_hour < 5 or login_hour > 22:
            score += 1
        if failed_attempts >= 3:
            score += 2
        if new_device == 1:
            score += 2
        if distance_km > 1000:
            score += 2
        if trusted_device == 0:
            score += 1

        if score <= 2:
            label = 0
        elif score <= 4:
            label = 1
        else:
            label = 2

        data.append([login_hour, failed_attempts, new_device, distance_km, trusted_device])
        labels.append(label)

    X = pd.DataFrame(
        data,
        columns=["login_hour", "failed_attempts", "new_device", "distance_km", "trusted_device"]
    )
    y = labels

    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=120, random_state=42)
    model.fit(X_train, y_train)
    return model


ML_MODEL = train_model()


def predict_risk(login_hour, failed_attempts, new_device, distance_km, trusted_device):
    X = pd.DataFrame([[
        login_hour, failed_attempts, new_device, distance_km, trusted_device
    ]], columns=[
        "login_hour", "failed_attempts", "new_device", "distance_km", "trusted_device"
    ])

    pred = ML_MODEL.predict(X)[0]
    proba = ML_MODEL.predict_proba(X)[0]

    mapping = {
        0: "Low Risk",
        1: "Medium Risk",
        2: "High Risk"
    }
    return mapping[pred], proba

# =========================================================
# HELPERS
# =========================================================
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def current_device_id():
    return getattr(g, "device_id", None)


def default_device_name():
    did = current_device_id() or str(uuid.uuid4())
    return f"Device-{did[:8]}"


def current_user():
    return session.get("user")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return fn(*args, **kwargs)
    return wrapper


def user_exists(username):
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    return row is not None


def create_user(username, password):
    db = get_db()
    db.execute(
        "INSERT INTO users(username, password, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), now_str())
    )
    db.commit()


def verify_user(username, password):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return False
    return check_password_hash(row["password"], password)


def add_trusted_device(username, device_id, device_name):
    db = get_db()
    existing = db.execute(
        "SELECT id FROM devices WHERE username=? AND device_id=?",
        (username, device_id)
    ).fetchone()

    if existing:
        db.execute("""
            UPDATE devices
            SET trusted=1, device_name=?
            WHERE username=? AND device_id=?
        """, (device_name, username, device_id))
    else:
        db.execute("""
            INSERT INTO devices(username, device_id, device_name, trusted, created_at)
            VALUES (?, ?, ?, 1, ?)
        """, (username, device_id, device_name, now_str()))
    db.commit()


def is_trusted_device(username, device_id):
    db = get_db()
    row = db.execute("""
        SELECT id FROM devices
        WHERE username=? AND device_id=? AND trusted=1
    """, (username, device_id)).fetchone()
    return row is not None


def get_user_devices(username):
    db = get_db()
    return db.execute("""
        SELECT device_id, device_name, trusted, created_at
        FROM devices
        WHERE username=?
        ORDER BY id DESC
    """, (username,)).fetchall()


def remove_device(username, device_id):
    db = get_db()
    db.execute("DELETE FROM devices WHERE username=? AND device_id=?", (username, device_id))
    db.commit()


def create_login_request(username, requester_device_id):
    db = get_db()
    token = str(uuid.uuid4())

    login_hour = datetime.now().hour
    failed_attempts = session.get("failed_attempts", 0)
    new_device = 1
    distance_km = round(random.uniform(1, 4000), 2)
    trusted_device = 1

    risk_label, _ = predict_risk(
        login_hour,
        failed_attempts,
        new_device,
        distance_km,
        trusted_device
    )

    db.execute("""
        INSERT INTO login_requests(
            request_token, username, requester_device_id, status, risk_result,
            login_hour, failed_attempts, new_device, distance_km, trusted_device, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        token, username, requester_device_id, "pending", risk_label,
        login_hour, failed_attempts, new_device, distance_km, trusted_device, now_str()
    ))
    db.commit()
    return token


def get_login_request(token):
    db = get_db()
    return db.execute("""
        SELECT *
        FROM login_requests
        WHERE request_token=?
    """, (token,)).fetchone()


def update_login_request_status(token, status, risk_result=""):
    db = get_db()
    db.execute("""
        UPDATE login_requests
        SET status=?, risk_result=?
        WHERE request_token=?
    """, (status, risk_result, token))
    db.commit()


def get_recent_login_requests(username):
    db = get_db()
    return db.execute("""
        SELECT request_token, status, risk_result, created_at
        FROM login_requests
        WHERE username=?
        ORDER BY id DESC
        LIMIT 10
    """, (username,)).fetchall()


def save_login_log(username, login_hour, failed_attempts, new_device, distance_km, trusted_device, risk_result):
    db = get_db()
    db.execute("""
        INSERT INTO login_logs(
            username, login_hour, failed_attempts, new_device,
            distance_km, trusted_device, risk_result, timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, login_hour, failed_attempts, new_device,
        distance_km, trusted_device, risk_result, now_str()
    ))
    db.commit()


def get_logs():
    db = get_db()
    return db.execute("""
        SELECT username, login_hour, failed_attempts, new_device,
               distance_km, trusted_device, risk_result, timestamp
        FROM login_logs
        ORDER BY id DESC
    """).fetchall()


def qr_image_data(url_text):
    qr = qrcode.QRCode(box_size=10, border=3)
    qr.add_data(url_text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

# =========================================================
# DEVICE COOKIE
# =========================================================
@app.before_request
def ensure_device():
    g.new_device_cookie = False
    device_id = request.cookies.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
        g.new_device_cookie = True
    g.device_id = device_id


@app.after_request
def persist_device_cookie(response):
    if getattr(g, "new_device_cookie", False):
        response.set_cookie(
            "device_id",
            g.device_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax"
        )
    return response

# =========================================================
# TEMPLATES
# =========================================================
BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
        :root {
            --bg: #070b14;
            --bg-soft: #0f1727;
            --card: rgba(17, 24, 39, 0.78);
            --card-2: rgba(15, 23, 42, 0.92);
            --border: rgba(255,255,255,0.08);
            --text: #e5eefc;
            --muted: #9fb0cf;
            --accent: #7c3aed;
            --accent-2: #06b6d4;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #f59e0b;
            --shadow: 0 10px 30px rgba(0,0,0,0.28);
            --radius: 22px;
        }

        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }

        body {
            margin: 0;
            font-family: Inter, system-ui, Arial, sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at top left, rgba(124,58,237,0.18), transparent 28%),
                radial-gradient(circle at top right, rgba(6,182,212,0.15), transparent 25%),
                linear-gradient(180deg, #050814 0%, #0b1020 100%);
            min-height: 100vh;
        }

        a { color: inherit; text-decoration: none; }

        .shell {
            width: min(1180px, calc(100% - 28px));
            margin: 0 auto;
            padding: 22px 0 40px;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 14px 18px;
            border: 1px solid var(--border);
            background: rgba(10, 15, 28, 0.72);
            backdrop-filter: blur(16px);
            border-radius: 20px;
            box-shadow: var(--shadow);
            position: sticky;
            top: 14px;
            z-index: 50;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-badge {
            width: 42px;
            height: 42px;
            border-radius: 14px;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            display: grid;
            place-items: center;
            font-weight: 800;
            color: white;
            box-shadow: 0 8px 24px rgba(124,58,237,0.35);
        }

        .brand h1 {
            margin: 0;
            font-size: 17px;
            line-height: 1.1;
        }

        .brand p {
            margin: 2px 0 0;
            font-size: 12px;
            color: var(--muted);
        }

        .nav {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .nav a {
            padding: 10px 14px;
            border-radius: 12px;
            color: var(--muted);
            transition: 0.2s ease;
        }

        .nav a:hover {
            background: rgba(255,255,255,0.05);
            color: white;
        }

        .hero {
            margin-top: 20px;
            display: grid;
            grid-template-columns: 1.4fr 1fr;
            gap: 18px;
        }

        .hero-card, .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            backdrop-filter: blur(16px);
        }

        .hero-card {
            padding: 32px;
            overflow: hidden;
            position: relative;
        }

        .hero-card::before {
            content: "";
            position: absolute;
            inset: auto -60px -60px auto;
            width: 220px;
            height: 220px;
            border-radius: 999px;
            background: radial-gradient(circle, rgba(124,58,237,0.24), transparent 70%);
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(124,58,237,0.16);
            color: #ddd6fe;
            font-size: 12px;
            border: 1px solid rgba(124,58,237,0.25);
        }

        .hero-card h2 {
            font-size: clamp(28px, 5vw, 46px);
            line-height: 1.03;
            margin: 18px 0 12px;
        }

        .hero-card p {
            color: var(--muted);
            font-size: 15px;
            max-width: 640px;
        }

        .hero-actions {
            margin-top: 22px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .btn {
            border: none;
            border-radius: 14px;
            padding: 13px 18px;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            transition: transform 0.15s ease, opacity 0.15s ease, box-shadow 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
        }

        .btn:hover { transform: translateY(-1px); }
        .btn:disabled { opacity: 0.7; cursor: not-allowed; transform: none; }

        .btn-primary {
            color: white;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            box-shadow: 0 12px 30px rgba(124,58,237,0.3);
        }

        .btn-ghost {
            color: white;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
        }

        .btn-danger {
            color: white;
            background: linear-gradient(135deg, #ef4444, #f97316);
        }

        .btn-success {
            color: white;
            background: linear-gradient(135deg, #16a34a, #10b981);
        }

        .mini-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 14px;
        }

        .stat {
            padding: 18px;
            border-radius: 18px;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
        }

        .stat .label {
            color: var(--muted);
            font-size: 12px;
        }

        .stat .value {
            margin-top: 8px;
            font-size: 18px;
            font-weight: 800;
            word-break: break-word;
        }

        .content-grid {
            margin-top: 18px;
            display: grid;
            grid-template-columns: 1fr;
            gap: 18px;
        }

        .auth-wrap {
            display: grid;
            place-items: center;
            margin-top: 24px;
        }

        .auth-card {
            width: min(100%, 520px);
            padding: 26px;
        }

        .auth-card h2, .card h2, .card h3 {
            margin-top: 0;
            margin-bottom: 12px;
        }

        .subtle {
            color: var(--muted);
            font-size: 14px;
        }

        .form-grid {
            display: grid;
            gap: 14px;
        }

        label {
            display: block;
            font-size: 13px;
            color: #c7d2fe;
            margin-bottom: 7px;
            font-weight: 600;
        }

        input {
            width: 100%;
            border: 1px solid rgba(255,255,255,0.08);
            outline: none;
            border-radius: 14px;
            background: rgba(255,255,255,0.04);
            color: white;
            padding: 14px 15px;
            font-size: 14px;
            transition: border-color 0.2s ease, background 0.2s ease;
        }

        input:focus {
            border-color: rgba(124,58,237,0.65);
            background: rgba(255,255,255,0.06);
        }

        .flash-wrap {
            margin-top: 18px;
            display: grid;
            gap: 10px;
        }

        .flash {
            padding: 14px 16px;
            border-radius: 16px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.05);
            box-shadow: var(--shadow);
            animation: slideDown 0.25s ease;
        }

        .flash.success { border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.10); }
        .flash.error { border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.10); }
        .flash.warning { border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.10); }
        .flash.info { border-color: rgba(6,182,212,0.35); background: rgba(6,182,212,0.10); }

        .card {
            padding: 22px;
        }

        .two-col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
        }

        .table-wrap {
            overflow-x: auto;
            border-radius: 18px;
            border: 1px solid var(--border);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 640px;
        }

        th, td {
            text-align: left;
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            font-size: 14px;
            vertical-align: top;
        }

        th {
            color: #c7d2fe;
            background: rgba(255,255,255,0.04);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        tr:hover td {
            background: rgba(255,255,255,0.03);
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            border: 1px solid transparent;
        }

        .pill-success {
            color: #86efac;
            background: rgba(34,197,94,0.12);
            border-color: rgba(34,197,94,0.25);
        }

        .pill-warning {
            color: #fcd34d;
            background: rgba(245,158,11,0.12);
            border-color: rgba(245,158,11,0.25);
        }

        .pill-danger {
            color: #fca5a5;
            background: rgba(239,68,68,0.12);
            border-color: rgba(239,68,68,0.25);
        }

        .pill-info {
            color: #7dd3fc;
            background: rgba(6,182,212,0.12);
            border-color: rgba(6,182,212,0.25);
        }

        .qr-box {
            display: grid;
            place-items: center;
            padding: 18px;
            border-radius: 24px;
            background: linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.03));
            border: 1px solid var(--border);
        }

        .qr-box img {
            width: min(100%, 290px);
            background: white;
            padding: 14px;
            border-radius: 20px;
        }

        .link-box {
            margin-top: 14px;
            padding: 14px;
            background: rgba(255,255,255,0.04);
            border-radius: 16px;
            border: 1px solid var(--border);
            word-break: break-all;
            color: #dbeafe;
        }

        .copy-row {
            margin-top: 12px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .risk-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }

        .risk-card {
            padding: 16px;
            border-radius: 18px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.04);
        }

        .risk-card .name {
            color: var(--muted);
            font-size: 12px;
        }

        .risk-card .num {
            margin-top: 8px;
            font-size: 24px;
            font-weight: 800;
        }

        .empty {
            padding: 24px;
            text-align: center;
            color: var(--muted);
            border: 1px dashed rgba(255,255,255,0.12);
            border-radius: 18px;
            background: rgba(255,255,255,0.03);
        }

        .footer-note {
            text-align: center;
            color: var(--muted);
            font-size: 12px;
            margin-top: 20px;
        }

        .spinner {
            display: none;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }

        .show-spinner .spinner {
            display: inline-block;
        }

        .status-banner {
            padding: 16px 18px;
            border-radius: 18px;
            border: 1px solid var(--border);
            margin-bottom: 16px;
            font-weight: 700;
        }

        .status-banner.pending {
            background: rgba(245,158,11,0.10);
            color: #fcd34d;
            border-color: rgba(245,158,11,0.25);
        }

        .status-banner.approved {
            background: rgba(34,197,94,0.10);
            color: #86efac;
            border-color: rgba(34,197,94,0.25);
        }

        .status-banner.blocked {
            background: rgba(239,68,68,0.10);
            color: #fca5a5;
            border-color: rgba(239,68,68,0.25);
        }

        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 980px) {
            .hero, .two-col {
                grid-template-columns: 1fr;
            }

            .risk-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 640px) {
            .shell {
                width: min(100% - 18px, 1180px);
                padding-top: 14px;
            }

            .topbar {
                flex-direction: column;
                align-items: stretch;
            }

            .nav {
                justify-content: space-between;
            }

            .hero-card, .card, .auth-card {
                padding: 18px;
            }

            .mini-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="topbar">
            <div class="brand">
                <div class="brand-badge">Q</div>
                <div>
                    <h1>QR Shield</h1>
                    <p>Machine-learning assisted device approval</p>
                </div>
            </div>

            <div class="nav">
                <a href="{{ url_for('home') }}">Home</a>
                {% if user %}
                    <a href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a href="{{ url_for('admin_logs') }}">Logs</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                {% else %}
                    <a href="{{ url_for('register') }}">Register</a>
                    <a href="{{ url_for('login') }}">Login</a>
                {% endif %}
            </div>
        </div>

        <div class="flash-wrap">
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                  <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}
        </div>

        {{ body|safe }}

        <div class="footer-note">
            QR Shield • Flask • SQLite • ML risk scoring • because ugly auth pages are a crime
        </div>
    </div>

    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast("Link copied to clipboard");
            }).catch(() => {
                showToast("Could not copy link");
            });
        }

        function showToast(message) {
            const toast = document.createElement("div");
            toast.className = "flash info";
            toast.style.position = "fixed";
            toast.style.right = "18px";
            toast.style.bottom = "18px";
            toast.style.zIndex = "9999";
            toast.style.maxWidth = "320px";
            toast.textContent = message;
            document.body.appendChild(toast);

            setTimeout(() => {
                toast.style.opacity = "0";
                toast.style.transform = "translateY(8px)";
                toast.style.transition = "all .25s ease";
            }, 1800);

            setTimeout(() => toast.remove(), 2200);
        }

        function lockButton(button) {
            if (!button) return;
            button.disabled = true;
            button.classList.add("show-spinner");
        }

        document.addEventListener("submit", function(e) {
            const form = e.target;
            if (form.matches(".loading-form")) {
                const btn = form.querySelector("button[type='submit']:focus") || form.querySelector("button[type='submit']");
                lockButton(btn);
            }
        });
    </script>

    {{ page_script|safe }}
</body>
</html>
"""


def render_page(title, body, page_script=""):
    return render_template_string(
        BASE_HTML,
        title=title,
        body=body,
        page_script=page_script,
        user=current_user(),
    )


def status_pill(status):
    if status == "approved":
        return '<span class="pill pill-success">Approved</span>'
    if status == "blocked":
        return '<span class="pill pill-danger">Blocked</span>'
    if status == "pending":
        return '<span class="pill pill-warning">Pending</span>'
    return f'<span class="pill pill-info">{status.title()}</span>'

# =========================================================
# ROUTES
# =========================================================
@app.route("/")
def home():
    body = f"""
    <section class="hero">
        <div class="hero-card">
            <div class="eyebrow">Secure QR verification • Trusted devices • ML risk engine</div>
            <h2>Authentication that behaves like a real system now.</h2>
            <p>
                QR Shield combines password login, trusted device linking, QR-based approval,
                and a lightweight machine learning risk model to evaluate suspicious login attempts.
            </p>
            <div class="hero-actions">
                <a class="btn btn-primary" href="{url_for('register')}">Create Account</a>
                <a class="btn btn-ghost" href="{url_for('login')}">Sign In</a>
            </div>
        </div>

        <div class="hero-card">
            <div class="mini-grid">
                <div class="stat">
                    <div class="label">Current Device</div>
                    <div class="value">{default_device_name()}</div>
                </div>
                <div class="stat">
                    <div class="label">Device ID</div>
                    <div class="value">{current_device_id()}</div>
                </div>
                <div class="stat">
                    <div class="label">Trusted Flow</div>
                    <div class="value">Password + QR Approval</div>
                </div>
                <div class="stat">
                    <div class="label">Risk Engine</div>
                    <div class="value">Low / Medium / High</div>
                </div>
            </div>
        </div>
    </section>
    """
    return render_page("Home", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        device_name = request.form.get("device_name", "").strip() or default_device_name()

        if not username or not password:
            flash("Please fill in all fields.", "warning")
            return redirect(url_for("register"))

        if user_exists(username):
            flash("That username already exists.", "error")
            return redirect(url_for("register"))

        create_user(username, password)
        add_trusted_device(username, current_device_id(), device_name)
        session["user"] = username
        flash("Account created successfully. This device is now trusted.", "success")
        return redirect(url_for("dashboard"))

    body = f"""
    <div class="auth-wrap">
        <div class="card auth-card">
            <h2>Create Account</h2>
            <p class="subtle">Register once and this device becomes your first trusted device.</p>
            <form method="post" class="form-grid loading-form">
                <div>
                    <label>Username</label>
                    <input name="username" type="text" placeholder="Choose a username" required>
                </div>
                <div>
                    <label>Password</label>
                    <input name="password" type="password" placeholder="Enter a secure password" required>
                </div>
                <div>
                    <label>Device Name</label>
                    <input name="device_name" type="text" value="{default_device_name()}">
                </div>
                <button class="btn btn-primary" type="submit">
                    <span class="spinner"></span>
                    <span class="btn-text">Create Account</span>
                </button>
            </form>
        </div>
    </div>
    """
    return render_page("Register", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "")
    failed_attempts = session.get("failed_attempts", 0)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        device_name = request.form.get("device_name", "").strip() or default_device_name()
        next_url = request.form.get("next", "").strip()

        if not username or not password:
            flash("Please fill in all fields.", "warning")
            return redirect(url_for("login", next=next_url))

        if not verify_user(username, password):
            session["failed_attempts"] = failed_attempts + 1
            flash("Invalid username or password.", "error")
            return redirect(url_for("login", next=next_url))

        session["failed_attempts"] = 0

        if is_trusted_device(username, current_device_id()):
            session["user"] = username
            add_trusted_device(username, current_device_id(), device_name)
            flash("Login successful on trusted device.", "success")
            return redirect(next_url or url_for("dashboard"))

        token = create_login_request(username, current_device_id())
        session["pending_login_token"] = token
        session["pending_login_user"] = username
        session["pending_login_device_name"] = device_name
        flash("New device detected. QR verification is required.", "info")
        return redirect(url_for("pending_login", token=token))

    body = f"""
    <div class="auth-wrap">
        <div class="card auth-card">
            <h2>Welcome back</h2>
            <p class="subtle">
                Sign in normally on trusted devices. New devices require QR approval.
            </p>
            <form method="post" class="form-grid loading-form">
                <input type="hidden" name="next" value="{next_url}">
                <div>
                    <label>Username</label>
                    <input name="username" type="text" placeholder="Enter your username" required>
                </div>
                <div>
                    <label>Password</label>
                    <input name="password" type="password" placeholder="Enter your password" required>
                </div>
                <div>
                    <label>Current Device Name</label>
                    <input name="device_name" type="text" value="{default_device_name()}">
                </div>
                <button class="btn btn-primary" type="submit">
                    <span class="spinner"></span>
                    <span class="btn-text">Sign In</span>
                </button>
            </form>
        </div>
    </div>
    """
    return render_page("Login", body)


@app.route("/pending/<token>")
def pending_login(token):
    row = get_login_request(token)
    if not row:
        return render_page("Pending Login", """
        <div class="card"><h2>Pending Login</h2><div class="empty">Login request not found.</div></div>
        """)

    if session.get("pending_login_token") != token:
        flash("This browser is not the original waiting device for that request.", "error")
        return redirect(url_for("login"))

    status = row["status"]
    username = row["username"]

    if status == "approved":
        session["user"] = username
        add_trusted_device(
            username,
            current_device_id(),
            session.get("pending_login_device_name", default_device_name())
        )
        session.pop("pending_login_token", None)
        session.pop("pending_login_user", None)
        session.pop("pending_login_device_name", None)
        flash("Login approved. This device is now trusted.", "success")
        return redirect(url_for("dashboard"))

    if status == "blocked":
        session.pop("pending_login_token", None)
        session.pop("pending_login_user", None)
        session.pop("pending_login_device_name", None)
        return render_page("Pending Login", """
        <div class="card">
            <h2>Pending Login</h2>
            <div class="status-banner blocked">This login request was blocked.</div>
            <a class="btn btn-ghost" href="/login">Back to Login</a>
        </div>
        """)

    approve_url = url_for("approve_qr", token=token, _external=True)
    qr_b64 = qr_image_data(approve_url)

    body = f"""
    <div class="two-col" style="margin-top:20px;">
        <div class="card">
            <div id="statusBanner" class="status-banner pending">Status: Pending approval</div>
            <h2>QR Verification Needed</h2>
            <p class="subtle">
                This device is not trusted yet. Scan the QR code with a trusted device to continue.
                If your camera opens a new tab, log in there and it will return to the approval page.
            </p>

            <div class="link-box">
                <strong>Approval Link</strong><br>
                <span id="approvalLink">{approve_url}</span>
            </div>

            <div class="copy-row">
                <button class="btn btn-primary" type="button" onclick="copyToClipboard(document.getElementById('approvalLink').textContent)">
                    Copy Link
                </button>
                <a class="btn btn-ghost" href="{approve_url}" target="_blank" rel="noopener">Open Approval Page</a>
            </div>
        </div>

        <div class="card">
            <div class="qr-box">
                <img src="data:image/png;base64,{qr_b64}" alt="QR Code">
            </div>
        </div>
    </div>

    <div class="content-grid">
        <div class="card">
            <h3>Live Request Status</h3>
            <div class="mini-grid">
                <div class="stat">
                    <div class="label">Request Token</div>
                    <div class="value">{token}</div>
                </div>
                <div class="stat">
                    <div class="label">Username</div>
                    <div class="value">{row["username"]}</div>
                </div>
            </div>
            <p class="subtle" id="statusText">Waiting for approval...</p>
        </div>
    </div>
    """

    page_script = f"""
    <script>
        const token = "{token}";
        let pollInterval = null;

        function updateStatusUI(status) {{
            const banner = document.getElementById("statusBanner");
            const text = document.getElementById("statusText");

            banner.className = "status-banner " + status;

            if (status === "pending") {{
                banner.textContent = "Status: Pending approval";
                text.textContent = "Waiting for approval from a trusted device...";
            }} else if (status === "approved") {{
                banner.textContent = "Status: Approved";
                text.textContent = "Approval received. Redirecting...";
            }} else if (status === "blocked") {{
                banner.textContent = "Status: Blocked";
                text.textContent = "This login request was blocked.";
            }}
        }}

        async function pollStatus() {{
            try {{
                const res = await fetch("/status/" + token, {{ cache: "no-store" }});
                const data = await res.json();
                updateStatusUI(data.status);

                if (data.status === "approved" || data.status === "blocked") {{
                    clearInterval(pollInterval);
                    setTimeout(() => window.location.reload(), 900);
                }}
            }} catch (err) {{
                console.error("Polling failed", err);
            }}
        }}

        pollStatus();
        pollInterval = setInterval(pollStatus, 3000);
    </script>
    """
    return render_page("Pending Login", body, page_script=page_script)


@app.route("/status/<token>")
def request_status(token):
    row = get_login_request(token)
    if not row:
        return jsonify({"status": "missing"}), 404
    return jsonify({
        "status": row["status"],
        "risk_result": row["risk_result"] or ""
    })


@app.route("/approve/<token>", methods=["GET", "POST"])
def approve_qr(token):
    row = get_login_request(token)
    if not row:
        return render_page("Approve QR", """
        <div class="card" style="margin-top:20px;">
            <h2>Approve Login</h2>
            <div class="empty">Invalid or missing approval request.</div>
        </div>
        """)

    username = row["username"]
    status = row["status"]

    if not current_user():
        return redirect(url_for("login", next=url_for("approve_qr", token=token)))

    if current_user() != username:
        return render_page("Approve QR", f"""
        <div class="card" style="margin-top:20px;">
            <h2>Approve Login</h2>
            <div class="status-banner blocked">
                You are logged in as {current_user()}, but this request belongs to {username}.
            </div>
        </div>
        """)

    if not is_trusted_device(username, current_device_id()):
        return render_page("Approve QR", """
        <div class="card" style="margin-top:20px;">
            <h2>Approve Login</h2>
            <div class="status-banner blocked">
                This device is not trusted for this account and cannot approve the login.
            </div>
        </div>
        """)

    login_hour = row["login_hour"]
    failed_attempts = row["failed_attempts"]
    new_device = row["new_device"]
    distance_km = row["distance_km"]
    trusted_device = row["trusted_device"]

    risk_label, proba = predict_risk(
        login_hour,
        failed_attempts,
        new_device,
        distance_km,
        trusted_device
    )

    if request.method == "POST" and status == "pending":
        action = request.form.get("action")

        if action == "approve":
            if risk_label == "High Risk":
                flash("High-risk request detected. Automatic approval is disabled.", "warning")
            else:
                update_login_request_status(token, "approved", risk_label)
                save_login_log(
                    username, login_hour, failed_attempts,
                    new_device, distance_km, trusted_device, risk_label
                )
                flash("Login approved successfully.", "success")
                return redirect(url_for("approve_qr", token=token))

        elif action == "block":
            update_login_request_status(token, "blocked", "Blocked")
            save_login_log(
                username, login_hour, failed_attempts,
                new_device, distance_km, trusted_device, "Blocked"
            )
            flash("Login request blocked.", "error")
            return redirect(url_for("approve_qr", token=token))

    if status == "approved":
        status_html = '<div class="status-banner approved">This login request has already been approved.</div>'
    elif status == "blocked":
        status_html = '<div class="status-banner blocked">This login request has been blocked.</div>'
    else:
        status_html = '<div class="status-banner pending">This login request is waiting for your decision.</div>'

    body = f"""
    <div class="content-grid" style="margin-top:20px;">
        <div class="card">
            {status_html}
            <h2>Approve Login Request</h2>
            <div class="mini-grid">
                <div class="stat">
                    <div class="label">Username</div>
                    <div class="value">{username}</div>
                </div>
                <div class="stat">
                    <div class="label">Created At</div>
                    <div class="value">{row["created_at"]}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>Machine Learning Risk Analysis</h3>
            <div class="mini-grid" style="margin-bottom:14px;">
                <div class="stat">
                    <div class="label">Login Hour</div>
                    <div class="value">{login_hour}</div>
                </div>
                <div class="stat">
                    <div class="label">Distance</div>
                    <div class="value">{distance_km:.2f} km</div>
                </div>
                <div class="stat">
                    <div class="label">Failed Attempts</div>
                    <div class="value">{failed_attempts}</div>
                </div>
                <div class="stat">
                    <div class="label">New Device</div>
                    <div class="value">Yes</div>
                </div>
            </div>

            <div class="status-banner {'approved' if risk_label == 'Low Risk' else 'pending' if risk_label == 'Medium Risk' else 'blocked'}">
                Predicted Risk: {risk_label}
            </div>

            <div class="risk-grid">
                <div class="risk-card">
                    <div class="name">Low Risk</div>
                    <div class="num">{float(proba[0]):.4f}</div>
                </div>
                <div class="risk-card">
                    <div class="name">Medium Risk</div>
                    <div class="num">{float(proba[1]):.4f}</div>
                </div>
                <div class="risk-card">
                    <div class="name">High Risk</div>
                    <div class="num">{float(proba[2]):.4f}</div>
                </div>
            </div>
        </div>
    """

    if status == "pending":
        if risk_label == "High Risk":
            body += """
            <div class="card">
                <h3>Decision</h3>
                <p class="subtle">This request is marked high risk. Blocking is strongly recommended.</p>
                <form method="post" class="loading-form">
                    <button class="btn btn-danger" type="submit" name="action" value="block">
                        <span class="spinner"></span>
                        <span class="btn-text">Block Login</span>
                    </button>
                </form>
            </div>
            """
        else:
            body += """
            <div class="card">
                <h3>Decision</h3>
                <p class="subtle">Approve if this login is genuinely yours. Otherwise block it.</p>
                <form method="post" class="loading-form">
                    <div style="display:flex; gap:12px; flex-wrap:wrap;">
                        <button class="btn btn-success" type="submit" name="action" value="approve">
                            <span class="spinner"></span>
                            <span class="btn-text">Approve Login</span>
                        </button>
                        <button class="btn btn-danger" type="submit" name="action" value="block">
                            <span class="spinner"></span>
                            <span class="btn-text">Block Login</span>
                        </button>
                    </div>
                </form>
            </div>
            """
    else:
        body += f"""
        <div class="card">
            <h3>Final Status</h3>
            <p>{status_pill(status)} {row["risk_result"] or ""}</p>
        </div>
        """

    body += "</div>"
    return render_page("Approve QR", body)


@app.route("/dashboard")
@login_required
def dashboard():
    username = current_user()
    devices = get_user_devices(username)
    requests_ = get_recent_login_requests(username)

    trusted_count = sum(1 for d in devices if d["trusted"] == 1)
    pending_count = sum(1 for r in requests_ if r["status"] == "pending")

    device_rows = ""
    for d in devices:
        current_tag = " <span class='pill pill-info'>Current</span>" if d["device_id"] == current_device_id() else ""
        unlink = ""
        if d["device_id"] != current_device_id():
            unlink = f'<a class="btn btn-ghost" href="{url_for("unlink_device", device_id=d["device_id"])}" style="padding:9px 12px; font-size:12px;">Unlink</a>'

        device_rows += f"""
        <tr>
            <td>{d["device_name"] or "Unnamed Device"}{current_tag}</td>
            <td>{"Yes" if d["trusted"] else "No"}</td>
            <td>{d["created_at"]}</td>
            <td>{unlink or "-"}</td>
        </tr>
        """

    request_rows = ""
    for r in requests_:
        request_rows += f"""
        <tr>
            <td>{r["request_token"]}</td>
            <td>{status_pill(r["status"])}</td>
            <td>{r["risk_result"] or "-"}</td>
            <td>{r["created_at"]}</td>
        </tr>
        """

    body = f"""
    <section class="hero" style="margin-top:20px;">
        <div class="hero-card">
            <div class="eyebrow">Dashboard</div>
            <h2>Welcome back, {username}</h2>
            <p>Manage trusted devices, review login requests, and keep an eye on authentication activity.</p>
        </div>

        <div class="hero-card">
            <div class="mini-grid">
                <div class="stat">
                    <div class="label">Trusted Devices</div>
                    <div class="value">{trusted_count}</div>
                </div>
                <div class="stat">
                    <div class="label">Pending Requests</div>
                    <div class="value">{pending_count}</div>
                </div>
                <div class="stat">
                    <div class="label">Current Device</div>
                    <div class="value">{default_device_name()}</div>
                </div>
                <div class="stat">
                    <div class="label">Device ID</div>
                    <div class="value">{current_device_id()}</div>
                </div>
            </div>
        </div>
    </section>

    <div class="content-grid">
        <div class="card">
            <h3>Trusted Devices</h3>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Device Name</th>
                        <th>Trusted</th>
                        <th>Added</th>
                        <th>Action</th>
                    </tr>
                    {device_rows if device_rows else '<tr><td colspan="4">No linked devices found.</td></tr>'}
                </table>
            </div>
        </div>

        <div class="card">
            <h3>Recent Login Requests</h3>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Token</th>
                        <th>Status</th>
                        <th>Risk</th>
                        <th>Created</th>
                    </tr>
                    {request_rows if request_rows else '<tr><td colspan="4">No login requests yet.</td></tr>'}
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("Dashboard", body)


@app.route("/unlink/<device_id>")
@login_required
def unlink_device(device_id):
    if device_id == current_device_id():
        flash("You cannot unlink the device you are currently using.", "warning")
        return redirect(url_for("dashboard"))

    remove_device(current_user(), device_id)
    flash("Device unlinked successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logs")
@login_required
def admin_logs():
    rows = get_logs()

    html_rows = ""
    for row in rows:
        html_rows += f"""
        <tr>
            <td>{row["username"]}</td>
            <td>{row["login_hour"]}</td>
            <td>{row["failed_attempts"]}</td>
            <td>{row["new_device"]}</td>
            <td>{row["distance_km"]:.2f}</td>
            <td>{row["trusted_device"]}</td>
            <td>{row["risk_result"]}</td>
            <td>{row["timestamp"]}</td>
        </tr>
        """

    body = f"""
    <div class="content-grid" style="margin-top:20px;">
        <div class="card">
            <h2>Authentication Logs</h2>
            <p class="subtle">A record of recent authentication outcomes.</p>
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>User</th>
                        <th>Hour</th>
                        <th>Failed Attempts</th>
                        <th>New Device</th>
                        <th>Distance</th>
                        <th>Trusted Device</th>
                        <th>Risk Result</th>
                        <th>Timestamp</th>
                    </tr>
                    {html_rows if html_rows else '<tr><td colspan="8">No logs yet.</td></tr>'}
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("Logs", body)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
