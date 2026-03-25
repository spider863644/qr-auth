import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime
import random

# -----------------------------
# DATABASE
# -----------------------------
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

# -----------------------------
# HELPERS
# -----------------------------
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_device_hash():
    device = st.session_state.get("device","unknown_device")
    return hash_text(device)

# -----------------------------
# ML RISK (dummy model)
# -----------------------------
def predict_risk(device, ip, hour):

    score = random.uniform(0,1)

    if score < 0.4:
        status = "Safe"
    elif score < 0.7:
        status = "Suspicious"
    else:
        status = "High Risk"

    return round(score,2), status

# -----------------------------
# REGISTER
# -----------------------------
def register():

    st.title("Register")

    user = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if st.button("Register"):

        hashed = hash_text(pw)

        c.execute("INSERT INTO users(username,password) VALUES(?,?)",(user,hashed))
        conn.commit()

        st.success("Account created")

# -----------------------------
# LOGIN
# -----------------------------
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

# -----------------------------
# LINK DEVICE
# -----------------------------
def link_device():

    st.header("Link This Device")

    device_hash = get_device_hash()

    if st.button("Link Device"):

        c.execute("INSERT INTO devices(username,device_hash) VALUES(?,?)",
        (st.session_state["user"],device_hash))

        conn.commit()

        st.success("Device linked")

# -----------------------------
# QR LOGIN
# -----------------------------
def qr_login():

    st.header("QR Login")

    token = str(uuid.uuid4())

    c.execute("INSERT INTO qr_tokens VALUES(?,?,?)",(token,"pending","pending"))
    conn.commit()

    base_url = st.secrets.get("APP_URL","http://localhost:8501")

    url = f"{base_url}/?qr_token={token}"

    qr = qrcode.make(url)

    buf = BytesIO()
    qr.save(buf)

    st.image(buf.getvalue())

    st.write("Scan QR with trusted device")

# -----------------------------
# DASHBOARD
# -----------------------------
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

# -----------------------------
# MAIN
# -----------------------------
menu = st.sidebar.selectbox("Menu",[
"Login",
"Register",
"QR Login"
])

if menu == "Login":
    login()

if menu == "Register":
    register()

if menu == "QR Login":
    qr_login()

if "user" in st.session_state:

    st.sidebar.success("Logged in")

    page = st.sidebar.selectbox("Dashboard",[
    "Dashboard",
    "Link Device"
    ])

    if page == "Dashboard":
        dashboard()

    if page == "Link Device":
        link_device()
