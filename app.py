import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime
import random

# -------------------------
# DATABASE
# -------------------------

conn = sqlite3.connect("auth.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
password TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS devices(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
device_hash TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS qr_tokens(
token TEXT,
username TEXT,
status TEXT
)
""")

conn.commit()

# -------------------------
# HELPERS
# -------------------------

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_device_hash():
    device = st.session_state.get("device","unknown_device")
    return hash_text(device)

# -------------------------
# ML RISK DEMO
# -------------------------

def predict_risk(device, ip, hour):

    score = random.uniform(0,1)

    if score < 0.4:
        status = "Safe"
    elif score < 0.7:
        status = "Suspicious"
    else:
        status = "High Risk"

    return round(score,2), status

# -------------------------
# HANDLE QR APPROVAL
# -------------------------

query_params = st.query_params

if "qr_token" in query_params:

    token = query_params["qr_token"]

    c.execute("SELECT username,status FROM qr_tokens WHERE token=?", (token,))
    result = c.fetchone()

    if result and result[1] == "pending":

        st.title("Approve Login Request")

        st.write("User:", result[0])

        if st.button("Approve Login"):

            c.execute(
                "UPDATE qr_tokens SET status='approved' WHERE token=?",
                (token,)
            )
            conn.commit()

            st.success("Login approved. You may close this page.")

            st.stop()

# -------------------------
# REGISTER
# -------------------------

def register():

    st.title("Register")

    user = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if st.button("Register"):

        hashed = hash_text(pw)

        c.execute("INSERT INTO users(username,password) VALUES(?,?)",(user,hashed))
        conn.commit()

        st.success("Account created")

# -------------------------
# LOGIN
# -------------------------

def login():

    st.title("Login")

    user = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if st.button("Login"):

        hashed = hash_text(pw)

        c.execute("SELECT * FROM users WHERE username=? AND password=?",(user,hashed))
        result = c.fetchone()

        if result:

            st.session_state["user"] = user
            st.success("Logged in")

        else:
            st.error("Invalid credentials")

# -------------------------
# LOGOUT
# -------------------------

def logout():

    if st.sidebar.button("Logout"):

        st.session_state.clear()
        st.success("Logged out")
        st.rerun()

# -------------------------
# LINK DEVICE
# -------------------------

def link_device():

    st.header("Link This Device")

    device_hash = get_device_hash()

    if st.button("Link Device"):

        c.execute("INSERT INTO devices(username,device_hash) VALUES(?,?)",
        (st.session_state["user"],device_hash))

        conn.commit()

        st.success("Device linked")

# -------------------------
# UNLINK DEVICE
# -------------------------

def unlink_device():

    st.header("Unlink Device")

    device_hash = get_device_hash()

    if st.button("Unlink This Device"):

        c.execute(
        "DELETE FROM devices WHERE username=? AND device_hash=?",
        (st.session_state["user"],device_hash)
        )

        conn.commit()

        st.success("Device removed")

# -------------------------
# QR LOGIN
# -------------------------

def qr_login():

    st.header("QR Login")

    token = str(uuid.uuid4())

    c.execute(
        "INSERT INTO qr_tokens(token,username,status) VALUES(?,?,?)",
        (token, st.session_state["user"], "pending")
    )
    conn.commit()

    base_url = st.secrets.get("APP_URL","http://localhost:8501")

    url = f"{base_url}/?qr_token={token}"

    qr = qrcode.make(url)

    buf = BytesIO()
    qr.save(buf)

    st.image(buf.getvalue())

    st.write("Scan QR with trusted device")

    if st.button("Check Login Status"):

        c.execute("SELECT status FROM qr_tokens WHERE token=?", (token,))
        status = c.fetchone()[0]

        if status == "approved":
            st.success("Login successful!")
        else:
            st.warning("Waiting for approval...")

# -------------------------
# DASHBOARD
# -------------------------

def dashboard():

    st.title("ML Authentication Dashboard")

    st.write("User:", st.session_state["user"])

    device = get_device_hash()
    ip = "127.0.0.1"

    score,status = predict_risk(device,ip,datetime.now().hour)

    st.metric("Risk Score",score)
    st.metric("Status",status)

    st.subheader("Linked Devices")

    c.execute("SELECT device_hash FROM devices WHERE username=?",
    (st.session_state["user"],))

    devices = c.fetchall()

    for d in devices:
        st.code(d[0][:20])

# -------------------------
# MENU
# -------------------------

menu = st.sidebar.selectbox("Menu",[
"Login",
"Register"
])

if menu == "Login":
    login()

if menu == "Register":
    register()

# -------------------------
# USER PANEL
# -------------------------

if "user" in st.session_state:

    logout()

    page = st.sidebar.selectbox("Dashboard",[
    "Dashboard",
    "Link Device",
    "Unlink Device",
    "QR Login"
    ])

    if page == "Dashboard":
        dashboard()

    if page == "Link Device":
        link_device()

    if page == "Unlink Device":
        unlink_device()

    if page == "QR Login":
        qr_login()
