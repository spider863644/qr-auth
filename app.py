import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
import random
import time
import extra_streamlit_components as stx

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(page_title="QR Login System", page_icon="🔐", layout="centered")

# =========================================================
# CONSTANTS
# =========================================================
DB_PATH = "auth.db"
SESSION_HOURS = 24
QR_MINUTES = 5

# =========================================================
# COOKIE MANAGER
# =========================================================
cookie_manager = stx.CookieManager(key="main_cookie_manager")

def load_cookies_once():
    if "_cookies_cache" not in st.session_state:
        st.session_state["_cookies_cache"] = cookie_manager.get_all(key="get_all_cookies")
    return st.session_state["_cookies_cache"]

def refresh_cookie_cache():
    st.session_state["_cookies_cache"] = cookie_manager.get_all(key="refresh_get_all_cookies")
    return st.session_state["_cookies_cache"]

# =========================================================
# DATABASE
# =========================================================
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    device_hash TEXT NOT NULL
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS qr_tokens(
    token TEXT PRIMARY KEY,
    username TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS sessions(
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""")

conn.commit()

# =========================================================
# SIMPLE MIGRATION
# =========================================================
def column_exists(table_name, column_name):
    c.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in c.fetchall()]
    return column_name in columns

# Example migration hook if needed later
# if not column_exists("qr_tokens", "approved_at"):
#     c.execute("ALTER TABLE qr_tokens ADD COLUMN approved_at TEXT")
#     conn.commit()

# =========================================================
# HELPERS
# =========================================================
def now_iso():
    return datetime.now().isoformat()

def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def device_hash() -> str:
    headers = getattr(st.context, "headers", {})
    user_agent = headers.get("user-agent", "unknown")
    ip = headers.get("x-forwarded-for", "unknown")
    return hash_text(f"{user_agent}|{ip}")

def predict_risk(device: str, ip: str, hour: int):
    score = random.uniform(0, 1)
    if score < 0.4:
        status = "Safe"
    elif score < 0.7:
        status = "Suspicious"
    else:
        status = "High Risk"
    return round(score, 2), status

# =========================================================
# CLEANUP
# =========================================================
def cleanup_old_entries():
    now = datetime.now()

    # Remove expired sessions
    c.execute("SELECT session_id, created_at FROM sessions")
    for session_id, created_at in c.fetchall():
        try:
            if now - parse_iso(created_at) > timedelta(hours=SESSION_HOURS):
                c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        except Exception:
            c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))

    # Remove expired QR tokens
    c.execute("SELECT token, created_at FROM qr_tokens")
    for token, created_at in c.fetchall():
        try:
            if now - parse_iso(created_at) > timedelta(minutes=QR_MINUTES):
                c.execute("DELETE FROM qr_tokens WHERE token=?", (token,))
        except Exception:
            c.execute("DELETE FROM qr_tokens WHERE token=?", (token,))

    conn.commit()

cleanup_old_entries()

# =========================================================
# SESSION MANAGEMENT
# =========================================================
def get_cookie_session_id():
    cookies = load_cookies_once()
    return cookies.get("user_session")

def create_session(username: str):
    session_id = str(uuid.uuid4())

    c.execute(
        "INSERT INTO sessions(session_id, username, created_at) VALUES (?, ?, ?)",
        (session_id, username, now_iso())
    )
    conn.commit()

    cookie_manager.set("user_session", session_id)
    st.session_state["_cookies_cache"] = {"user_session": session_id}
    st.session_state["user"] = username
    st.session_state["session_id"] = session_id

def get_session_user():
    session_id = get_cookie_session_id()
    if not session_id:
        return None

    c.execute(
        "SELECT username, created_at FROM sessions WHERE session_id=?",
        (session_id,)
    )
    row = c.fetchone()
    if not row:
        return None

    username, created_at = row

    try:
        created_dt = parse_iso(created_at)
    except Exception:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        cookie_manager.delete("user_session")
        st.session_state["_cookies_cache"] = {}
        return None

    if datetime.now() - created_dt > timedelta(hours=SESSION_HOURS):
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        cookie_manager.delete("user_session")
        st.session_state["_cookies_cache"] = {}
        return None

    return username

def logout_user():
    session_id = get_cookie_session_id()
    if session_id:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()

    cookie_manager.delete("user_session")
    st.session_state["_cookies_cache"] = {}

    for key in list(st.session_state.keys()):
        if key != "_cookies_cache":
            del st.session_state[key]

    st.rerun()

# Restore login from DB-backed session
existing_user = get_session_user()
if existing_user:
    st.session_state["user"] = existing_user

# =========================================================
# QR TOKEN HELPERS
# =========================================================
def create_qr_token():
    token = str(uuid.uuid4())
    c.execute(
        "INSERT INTO qr_tokens(token, username, status, created_at) VALUES (?, ?, ?, ?)",
        (token, "", "pending", now_iso())
    )
    conn.commit()
    return token

def get_qr_status(token: str):
    c.execute(
        "SELECT username, status, created_at FROM qr_tokens WHERE token=?",
        (token,)
    )
    return c.fetchone()

def approve_qr_token(token: str, username: str):
    c.execute(
        "UPDATE qr_tokens SET username=?, status='approved' WHERE token=? AND status='pending'",
        (username, token)
    )
    conn.commit()

def delete_qr_token(token: str):
    c.execute("DELETE FROM qr_tokens WHERE token=?", (token,))
    conn.commit()

def qr_is_expired(created_at: str) -> bool:
    try:
        return datetime.now() - parse_iso(created_at) > timedelta(minutes=QR_MINUTES)
    except Exception:
        return True

# =========================================================
# AUTH PAGES
# =========================================================
def register():
    st.title("Register")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Register", use_container_width=True):
        u = u.strip()

        if not u or not p:
            st.error("Username and password are required.")
            return

        try:
            c.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (u, hash_text(p))
            )
            conn.commit()
            st.success("Account created successfully.")
        except sqlite3.IntegrityError:
            st.error("Username already exists.")

def login():
    st.title("Login")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login", use_container_width=True):
        u = u.strip()

        c.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (u, hash_text(p))
        )
        user = c.fetchone()

        if user:
            create_session(u)
            st.success("Logged in successfully.")
            time.sleep(0.5)
            st.rerun()
        else:
            st.error("Invalid username or password.")

# =========================================================
# QR APPROVAL PAGE
# =========================================================
def qr_approval_page(token: str):
    st.title("Approve QR Login")

    row = get_qr_status(token)
    if not row:
        st.error("This QR request does not exist or has expired.")
        st.stop()

    username, status, created_at = row

    if qr_is_expired(created_at):
        delete_qr_token(token)
        st.error("This QR code has expired.")
        st.stop()

    approving_user = get_session_user()
    if not approving_user:
        st.warning("You must already be logged in on this phone/browser to approve this login.")
        st.stop()

    remaining = timedelta(minutes=QR_MINUTES) - (datetime.now() - parse_iso(created_at))
    seconds_left = max(0, int(remaining.total_seconds()))

    st.info(f"Logged in as: {approving_user}")
    st.caption(f"QR expires in about {seconds_left} seconds.")

    if status == "approved":
        st.success(f"This login has already been approved for {username}.")
        st.stop()

    if st.button("Approve Login", use_container_width=True):
        approve_qr_token(token, approving_user)
        st.success("Login approved. You can close this tab now.")
        st.stop()

    st.stop()

# =========================================================
# DEVICE PAGES
# =========================================================
def link_device():
    st.subheader("Link Device")
    current_user = st.session_state["user"]
    current_hash = device_hash()

    if st.button("Link this device", use_container_width=True):
        c.execute(
            "SELECT id FROM devices WHERE username=? AND device_hash=?",
            (current_user, current_hash)
        )
        exists = c.fetchone()

        if exists:
            st.info("This device is already linked.")
        else:
            c.execute(
                "INSERT INTO devices(username, device_hash) VALUES (?, ?)",
                (current_user, current_hash)
            )
            conn.commit()
            st.success("Device linked.")

def unlink_device():
    st.subheader("Unlink Device")
    current_user = st.session_state["user"]
    current_hash = device_hash()

    if st.button("Unlink this device", use_container_width=True):
        c.execute(
            "DELETE FROM devices WHERE username=? AND device_hash=?",
            (current_user, current_hash)
        )
        conn.commit()
        st.success("Device removed.")

# =========================================================
# QR LOGIN PAGE (PC / LAPTOP)
# =========================================================
def qr_login():
    st.title("QR Login")

    # Create token once and keep it stable across reruns
    if "qr_token" not in st.session_state:
        st.session_state["qr_token"] = create_qr_token()

    token = st.session_state["qr_token"]

    row = get_qr_status(token)
    if not row:
        st.session_state["qr_token"] = create_qr_token()
        token = st.session_state["qr_token"]
        row = get_qr_status(token)

    username, status, created_at = row

    if qr_is_expired(created_at):
        delete_qr_token(token)
        if "qr_token" in st.session_state:
            del st.session_state["qr_token"]
        st.warning("QR code expired. Generating a new one...")
        time.sleep(1)
        st.rerun()

    base_url = st.secrets.get("APP_URL", "http://localhost:8501").rstrip("/")
    qr_url = f"{base_url}/?qr_token={token}"

    qr = qrcode.make(qr_url)
    buf = BytesIO()
    qr.save(buf)

    st.image(buf.getvalue(), caption="Scan this with your logged-in phone", use_container_width=False)

    created_dt = parse_iso(created_at)
    remaining = timedelta(minutes=QR_MINUTES) - (datetime.now() - created_dt)
    seconds_left = max(0, int(remaining.total_seconds()))
    minutes = seconds_left // 60
    seconds = seconds_left % 60

    st.caption(f"Expires in {minutes:02d}:{seconds:02d}")

    if status == "approved" and username:
        create_session(username)
        delete_qr_token(token)
        if "qr_token" in st.session_state:
            del st.session_state["qr_token"]
        st.success(f"Logged in as {username}.")
        time.sleep(0.8)
        st.rerun()
    else:
        st.warning("Waiting for approval...")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Generate New QR", use_container_width=True):
                delete_qr_token(token)
                st.session_state["qr_token"] = create_qr_token()
                st.rerun()

        with col2:
            st.link_button("Open approval link", qr_url, use_container_width=True)

        # Near real-time auto-check
        time.sleep(1)
        st.rerun()

# =========================================================
# DASHBOARD
# =========================================================
def dashboard():
    current_user = st.session_state["user"]

    st.title("ML Security Dashboard")
    st.write(f"Welcome, **{current_user}**")

    headers = getattr(st.context, "headers", {})
    ip = headers.get("x-forwarded-for", "127.0.0.1")
    device = device_hash()

    score, status = predict_risk(device, ip, datetime.now().hour)

    col1, col2 = st.columns(2)
    col1.metric("Risk Score", score)
    col2.metric("Status", status)

    st.subheader("Trusted Devices")

    c.execute(
        "SELECT device_hash FROM devices WHERE username=?",
        (current_user,)
    )
    rows = c.fetchall()

    if rows:
        for row in rows:
            st.code(row[0][:24])
    else:
        st.info("No linked devices yet.")

# =========================================================
# QUERY PARAM ROUTING
# =========================================================
query = st.query_params
if "qr_token" in query:
    token_value = query["qr_token"]
    if isinstance(token_value, list):
        token_value = token_value[0]
    qr_approval_page(token_value)

# =========================================================
# MAIN APP
# =========================================================
if "user" not in st.session_state:
    menu = st.sidebar.selectbox("Menu", ["Login", "Register", "QR Login"])

    if menu == "Login":
        login()
    elif menu == "Register":
        register()
    elif menu == "QR Login":
        qr_login()
else:
    if st.sidebar.button("Logout", use_container_width=True):
        logout_user()

    page = st.sidebar.selectbox("Dashboard", ["Dashboard", "Link Device", "Unlink Device"])

    if page == "Dashboard":
        dashboard()
    elif page == "Link Device":
        link_device()
    elif page == "Unlink Device":
        unlink_device()
