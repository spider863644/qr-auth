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
    make_response, render_template_string, flash
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
    db.execute("""
        INSERT INTO login_requests(request_token, username, requester_device_id, status, risk_result, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (token, username, requester_device_id, "pending", "", now_str()))
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
    qr = qrcode.QRCode(box_size=8, border=4)
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
<html>
<head>
    <meta charset="utf-8">
    <title>{{ title }}</title>
    {% if refresh %}
    <meta http-equiv="refresh" content="{{ refresh }}">
    {% endif %}
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 30px auto;
            padding: 0 18px;
            line-height: 1.5;
            background: #f7f7f8;
            color: #111;
        }
        .card {
            background: #fff;
            padding: 18px;
            border-radius: 14px;
            margin-bottom: 18px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.06);
        }
        input, button {
            padding: 10px;
            margin: 6px 0;
            width: 100%;
            box-sizing: border-box;
        }
        button {
            cursor: pointer;
        }
        a.button {
            display: inline-block;
            padding: 10px 14px;
            background: #111;
            color: #fff;
            text-decoration: none;
            border-radius: 10px;
        }
        .muted { color: #666; font-size: 14px; }
        .success { color: green; }
        .error { color: #b00020; }
        .warn { color: #9a6700; }
        .nav a {
            margin-right: 10px;
        }
        code {
            word-break: break-all;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        .flash {
            padding: 10px;
            border-radius: 10px;
            background: #eef2ff;
            margin-bottom: 14px;
        }
    </style>
</head>
<body>
    <div class="card nav">
        <a href="{{ url_for('home') }}">Home</a>
        {% if user %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        {% else %}
            <a href="{{ url_for('register') }}">Register</a>
            <a href="{{ url_for('login') }}">Login</a>
        {% endif %}
    </div>

    <div class="card">
        <div><strong>Current device:</strong> {{ device_name }}</div>
        <div class="muted"><strong>Device ID:</strong> {{ device_id }}</div>
        {% if user %}
        <div class="muted"><strong>Logged in as:</strong> {{ user }}</div>
        {% endif %}
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="flash">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {{ body|safe }}
</body>
</html>
"""


def render_page(title, body, refresh=None):
    return render_template_string(
        BASE_HTML,
        title=title,
        body=body,
        refresh=refresh,
        user=current_user(),
        device_id=current_device_id(),
        device_name=default_device_name(),
    )


# =========================================================
# ROUTES
# =========================================================
@app.route("/")
def home():
    body = """
    <div class="card">
        <h2>ML QR Authentication System</h2>
        <p>This Flask version does the flow properly.</p>
        <ul>
            <li>Register on first device and it becomes trusted</li>
            <li>Login on a trusted device goes straight in</li>
            <li>Login on a new device shows a QR verification link</li>
            <li>Trusted device scans the QR and approves the login</li>
            <li>Approved device becomes trusted too</li>
            <li>Simple ML risk scoring is included</li>
        </ul>
    </div>
    """
    return render_page("Home", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        device_name = request.form.get("device_name", "").strip() or default_device_name()

        if not username or not password:
            flash("Fill in all fields.")
            return redirect(url_for("register"))

        if user_exists(username):
            flash("Username already exists.")
            return redirect(url_for("register"))

        create_user(username, password)
        add_trusted_device(username, current_device_id(), device_name)
        session["user"] = username
        flash("Account created. This device is now the first trusted device.")
        return redirect(url_for("dashboard"))

    body = f"""
    <div class="card">
        <h2>Register</h2>
        <form method="post">
            <label>Username</label>
            <input name="username" type="text" required>
            <label>Password</label>
            <input name="password" type="password" required>
            <label>Device Name</label>
            <input name="device_name" type="text" value="{default_device_name()}">
            <button type="submit">Create Account</button>
        </form>
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
            flash("Fill in all fields.")
            return redirect(url_for("login", next=next_url))

        if not verify_user(username, password):
            session["failed_attempts"] = failed_attempts + 1
            flash("Invalid username or password.")
            return redirect(url_for("login", next=next_url))

        session["failed_attempts"] = 0

        if is_trusted_device(username, current_device_id()):
            session["user"] = username
            add_trusted_device(username, current_device_id(), device_name)
            flash("Login successful on trusted device.")
            return redirect(next_url or url_for("dashboard"))

        token = create_login_request(username, current_device_id())
        session["pending_login_token"] = token
        session["pending_login_user"] = username
        session["pending_login_device_name"] = device_name
        return redirect(url_for("pending_login", token=token))

    body = f"""
    <div class="card">
        <h2>Login</h2>
        <form method="post">
            <input type="hidden" name="next" value="{next_url}">
            <label>Username</label>
            <input name="username" type="text" required>
            <label>Password</label>
            <input name="password" type="password" required>
            <label>Current Device Name</label>
            <input name="device_name" type="text" value="{default_device_name()}">
            <button type="submit">Login</button>
        </form>
        <p class="muted">If this device is not trusted, a QR code will be generated for approval.</p>
    </div>
    """
    return render_page("Login", body)


@app.route("/pending/<token>")
def pending_login(token):
    row = get_login_request(token)
    if not row:
        return render_page("Pending Login", """
        <div class="card"><h2>Pending Login</h2><p class="error">Login request not found.</p></div>
        """)

    if session.get("pending_login_token") != token:
        flash("This browser is not the original waiting device for that login request.")
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
        flash("Login approved. This device is now trusted.")
        return redirect(url_for("dashboard"))

    if status == "blocked":
        session.pop("pending_login_token", None)
        session.pop("pending_login_user", None)
        session.pop("pending_login_device_name", None)
        return render_page("Pending Login", """
        <div class="card">
            <h2>Pending Login</h2>
            <p class="error">This login request was blocked.</p>
            <a class="button" href="/login">Back to Login</a>
        </div>
        """)

    approve_url = url_for("approve_qr", token=token, _external=True)
    qr_b64 = qr_image_data(approve_url)

    body = f"""
    <div class="card">
        <h2>QR Verification Needed</h2>
        <p>This device is not trusted yet. Scan this QR code with a trusted device.</p>
        <img src="data:image/png;base64,{qr_b64}" alt="QR Code">
        <p class="muted">If your camera opens a new tab and asks you to log in, that's fine. After login it will return to the approval page automatically. Miracles do happen.</p>
        <p><strong>Approval Link:</strong><br><code>{approve_url}</code></p>
        <p><strong>Status:</strong> pending</p>
        <p class="muted">This page refreshes automatically every 5 seconds.</p>
    </div>
    """
    return render_page("Pending Login", body, refresh=5)


@app.route("/approve/<token>", methods=["GET", "POST"])
def approve_qr(token):
    row = get_login_request(token)
    if not row:
        return render_page("Approve QR", """
        <div class="card"><h2>Approve Login</h2><p class="error">Invalid or missing approval request.</p></div>
        """)

    username = row["username"]
    status = row["status"]

    if not current_user():
        return redirect(url_for("login", next=url_for("approve_qr", token=token)))

    if current_user() != username:
        return render_page("Approve QR", f"""
        <div class="card">
            <h2>Approve Login</h2>
            <p class="error">You are logged in as <strong>{current_user()}</strong>, but this request belongs to <strong>{username}</strong>.</p>
            <p>Log into the correct trusted account to approve it. Humans do love making account mix-ups.</p>
        </div>
        """)

    if not is_trusted_device(username, current_device_id()):
        return render_page("Approve QR", """
        <div class="card">
            <h2>Approve Login</h2>
            <p class="error">This device is not trusted for this account, so it cannot approve the login.</p>
        </div>
        """)

    login_hour = datetime.now().hour
    failed_attempts = 0
    new_device = 1
    distance_km = random.uniform(1, 4000)
    trusted_device = 1

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
                flash("High-risk request. Approval was not allowed automatically.")
            else:
                update_login_request_status(token, "approved", risk_label)
                save_login_log(
                    username, login_hour, failed_attempts,
                    new_device, distance_km, trusted_device, risk_label
                )
                flash("Login approved. The waiting device can now sign in.")
                return redirect(url_for("approve_qr", token=token))

        elif action == "block":
            update_login_request_status(token, "blocked", "Blocked")
            save_login_log(
                username, login_hour, failed_attempts,
                new_device, distance_km, trusted_device, "Blocked"
            )
            flash("Login blocked.")
            return redirect(url_for("approve_qr", token=token))

    status_block = f"""
    <p><strong>Username:</strong> {username}</p>
    <p><strong>Status:</strong> {status}</p>
    <p class="muted"><strong>Created:</strong> {row["created_at"]}</p>
    """

    risk_block = f"""
    <div class="card">
        <h3>Machine Learning Risk Analysis</h3>
        <p><strong>Login Hour:</strong> {login_hour}</p>
        <p><strong>Failed Attempts:</strong> {failed_attempts}</p>
        <p><strong>New Device:</strong> Yes</p>
        <p><strong>Distance (km):</strong> {distance_km:.2f}</p>
        <p><strong>Trusted Approver Device:</strong> Yes</p>
        <p><strong>Prediction:</strong> {risk_label}</p>
        <p class="muted">
            Low: {float(proba[0]):.4f} |
            Medium: {float(proba[1]):.4f} |
            High: {float(proba[2]):.4f}
        </p>
    </div>
    """

    buttons = ""
    if status == "pending":
        if risk_label == "High Risk":
            buttons = """
            <p class="warn">High-risk login detected. You can block it below.</p>
            <form method="post">
                <button type="submit" name="action" value="block">Block Login</button>
            </form>
            """
        else:
            buttons = """
            <form method="post">
                <button type="submit" name="action" value="approve">Approve Login</button>
                <button type="submit" name="action" value="block">Block Login</button>
            </form>
            """
    else:
        buttons = f'<p><strong>Final Status:</strong> {status}</p>'

    body = f"""
    <div class="card">
        <h2>Approve Login Request</h2>
        {status_block}
    </div>
    {risk_block}
    <div class="card">
        {buttons}
    </div>
    """
    return render_page("Approve QR", body)


@app.route("/dashboard")
@login_required
def dashboard():
    username = current_user()
    devices = get_user_devices(username)
    requests_ = get_recent_login_requests(username)

    device_rows = ""
    for d in devices:
        current_tag = " (Current Device)" if d["device_id"] == current_device_id() else ""
        unlink = ""
        if d["device_id"] != current_device_id():
            unlink = f'<a class="button" href="{url_for("unlink_device", device_id=d["device_id"])}">Unlink</a>'
        device_rows += f"""
        <tr>
            <td>{d["device_name"] or "Unnamed Device"}{current_tag}</td>
            <td>{"Yes" if d["trusted"] else "No"}</td>
            <td>{d["created_at"]}</td>
            <td>{unlink}</td>
        </tr>
        """

    request_rows = ""
    for r in requests_:
        request_rows += f"""
        <tr>
            <td>{r["request_token"]}</td>
            <td>{r["status"]}</td>
            <td>{r["risk_result"] or "-"}</td>
            <td>{r["created_at"]}</td>
        </tr>
        """

    body = f"""
    <div class="card">
        <h2>Dashboard</h2>
        <p>Welcome, <strong>{username}</strong>.</p>
    </div>

    <div class="card">
        <h3>Trusted Devices</h3>
        <table>
            <tr>
                <th>Device Name</th>
                <th>Trusted</th>
                <th>Added</th>
                <th>Action</th>
            </tr>
            {device_rows if device_rows else '<tr><td colspan="4">No linked devices.</td></tr>'}
        </table>
    </div>

    <div class="card">
        <h3>Recent Login Requests</h3>
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

    <div class="card">
        <p><a class="button" href="{url_for('admin_logs')}">View Authentication Logs</a></p>
    </div>
    """
    return render_page("Dashboard", body)


@app.route("/unlink/<device_id>")
@login_required
def unlink_device(device_id):
    if device_id == current_device_id():
        flash("You cannot unlink the device you are currently using.")
        return redirect(url_for("dashboard"))

    remove_device(current_user(), device_id)
    flash("Device unlinked.")
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
    <div class="card">
        <h2>Authentication Logs</h2>
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
    """
    return render_page("Logs", body)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)
