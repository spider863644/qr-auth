import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
import random
import extra_streamlit_components as stx

# ------------------------
# COOKIE MANAGER
# ------------------------
cookie_manager = stx.CookieManager()
cookies = cookie_manager.get_all()

# ------------------------
# DATABASE
# ------------------------
conn = sqlite3.connect("auth.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY,
username TEXT UNIQUE,
password TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS devices(
username TEXT,
device_hash TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS qr_tokens(
token TEXT PRIMARY KEY,
username TEXT,
status TEXT,
created_at TIMESTAMP
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS sessions(
session_id TEXT PRIMARY KEY,
username TEXT,
created_at TIMESTAMP
)
""")

conn.commit()

# ------------------------
# CLEANUP OLD ENTRIES
# ------------------------
def cleanup_old_entries():
    now = datetime.now()
    # cleanup sessions
    c.execute("SELECT session_id, created_at FROM sessions")
    for session_id, created_at in c.fetchall():
        if now - datetime.fromisoformat(created_at) > timedelta(hours=24):
            c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
    # cleanup QR tokens
    c.execute("SELECT token, created_at FROM qr_tokens")
    for token, created_at in c.fetchall():
        if now - datetime.fromisoformat(created_at) > timedelta(hours=24):
            c.execute("DELETE FROM qr_tokens WHERE token=?", (token,))
    conn.commit()

cleanup_old_entries()

# ------------------------
# HELPERS
# ------------------------
def hash_text(t):
    return hashlib.sha256(t.encode()).hexdigest()

def device_hash():
    return hash_text("demo_device")

def create_session(username):
    session_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    c.execute("INSERT INTO sessions(session_id, username, created_at) VALUES(?,?,?)",
              (session_id, username, now))
    conn.commit()
    cookie_manager.set("user_session", session_id)
    st.session_state["user"] = username

def get_session():
    session_id = cookies.get("user_session")
    if not session_id:
        return None
    c.execute("SELECT username, created_at FROM sessions WHERE session_id=?", (session_id,))
    row = c.fetchone()
    if row:
        username, created_at = row
        if datetime.now() - datetime.fromisoformat(created_at) > timedelta(hours=24):
            # session expired
            c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
            conn.commit()
            cookie_manager.delete("user_session")
            return None
        return username
    return None

def logout_user():
    session_id = cookies.get("user_session")
    if session_id:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        cookie_manager.delete("user_session")
    st.session_state.clear()
    st.experimental_rerun()

# ------------------------
# ML RISK DEMO
# ------------------------
def predict_risk(device, ip, hour):
    score = random.uniform(0, 1)
    if score < 0.4:
        status = "Safe"
    elif score < 0.7:
        status = "Suspicious"
    else:
        status = "High Risk"
    return round(score, 2), status

# ------------------------
# QR APPROVAL (PHONE)
# ------------------------
query = st.query_params
if "qr_token" in query:
    token = query["qr_token"][0]
    st.title("Approve QR Login")

    approving_user = get_session()
    if not approving_user:
        st.warning("You must be logged in to approve this login.")
        st.stop()

    st.write(f"Logged in as: **{approving_user}**")

    if st.button("Approve Login"):
        c.execute("UPDATE qr_tokens SET status='approved', username=? WHERE token=?",
                  (approving_user, token))
        conn.commit()
        st.success("Login approved. You may close this tab.")
    st.stop()

# ------------------------
# REGISTER
# ------------------------
def register():
    st.title("Register")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Register"):
        try:
            c.execute("INSERT INTO users(username,password) VALUES(?,?)", (u, hash_text(p)))
            conn.commit()
            st.success("Account created")
        except sqlite3.IntegrityError:
            st.error("Username already exists")

# ------------------------
# LOGIN
# ------------------------
def login():
    st.title("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, hash_text(p)))
        if c.fetchone():
            create_session(u)
            st.success("Logged in")
            st.experimental_rerun()
        else:
            st.error("Invalid login")

# ------------------------
# LINK DEVICE
# ------------------------
def link_device():
    st.header("Link Device")
    if st.button("Link this device"):
        c.execute("INSERT INTO devices(username, device_hash) VALUES(?,?)",
                  (st.session_state["user"], device_hash()))
        conn.commit()
        st.success("Device linked")

# ------------------------
# UNLINK DEVICE
# ------------------------
def unlink_device():
    st.header("Unlink Device")
    if st.button("Unlink this device"):
        c.execute("DELETE FROM devices WHERE username=? AND device_hash=?",
                  (st.session_state["user"], device_hash()))
        conn.commit()
        st.success("Device removed")

# ------------------------
# QR LOGIN (LAPTOP)
# ------------------------
def qr_login():
    st.title("QR Login")

    if "qr_token" not in st.session_state:
        token = str(uuid.uuid4())
        st.session_state["qr_token"] = token
        now = datetime.now().isoformat()
        c.execute("INSERT INTO qr_tokens(token,username,status,created_at) VALUES(?,?,?,?)",
                  (token, "", "pending", now))
        conn.commit()
    else:
        token = st.session_state["qr_token"]

    base_url = st.secrets.get("APP_URL", "http://localhost:8501")
    url = f"{base_url}/?qr_token={token}"

    qr = qrcode.make(url)
    buf = BytesIO()
    qr.save(buf)
    st.image(buf.getvalue())
    st.write("Scan this with your logged-in device")

    status_placeholder = st.empty()
    # Auto-poll the token
    c.execute("SELECT username, status FROM qr_tokens WHERE token=?", (token,))
    row = c.fetchone()
    if row and row[1] == "approved" and row[0]:
        create_session(row[0])
        st.success(f"Logged in as {row[0]} successfully")
        st.experimental_rerun()
    else:
        status_placeholder.warning("Waiting for approval...")

# ------------------------
# DASHBOARD
# ------------------------
def dashboard():
    st.title("ML Security Dashboard")
    device = device_hash()
    ip = "127.0.0.1"
    score, status = predict_risk(device, ip, datetime.now().hour)
    st.metric("Risk Score", score)
    st.metric("Status", status)
    st.subheader("Trusted Devices")
    c.execute("SELECT device_hash FROM devices WHERE username=?", (st.session_state["user"],))
    for d in c.fetchall():
        st.code(d[0][:20])

# ------------------------
# MAIN
# ------------------------
user = get_session()
if user:
    st.session_state["user"] = user

if "user" not in st.session_state:
    menu = st.sidebar.selectbox("Menu", ["Login", "Register", "QR Login"])
    if menu == "Login":
        login()
    elif menu == "Register":
        register()
    elif menu == "QR Login":
        qr_login()
else:
    if st.sidebar.button("Logout"):
        logout_user()
    page = st.sidebar.selectbox("Dashboard", ["Dashboard", "Link Device", "Unlink Device"])
    if page == "Dashboard":
        dashboard()
    elif page == "Link Device":
        link_device()
    elif page == "Unlink Device":
        unlink_device()
