import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime
import random

# --------------------
# DATABASE
# --------------------

conn = sqlite3.connect("auth.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY,
username TEXT,
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
token TEXT,
username TEXT,
status TEXT
)
""")

conn.commit()

# --------------------
# HELPERS
# --------------------

def hash_text(t):
    return hashlib.sha256(t.encode()).hexdigest()

def device_hash():
    return hash_text("demo_device")

# --------------------
# ML RISK DEMO
# --------------------

def predict_risk(device,ip,hour):

    score=random.uniform(0,1)

    if score<0.4:
        status="Safe"
    elif score<0.7:
        status="Suspicious"
    else:
        status="High Risk"

    return round(score,2),status

# --------------------
# QR APPROVAL (PHONE)
# --------------------

query=st.query_params

if "qr_token" in query:

    token=query["qr_token"]

    if "user" not in st.session_state:
        st.warning("Login first to approve QR request")
        st.stop()

    c.execute("SELECT status FROM qr_tokens WHERE token=?", (token,))
    row=c.fetchone()

    if row and row[0]=="pending":

        st.title("Approve Login")

        if st.button("Approve Login"):

            c.execute(
            "UPDATE qr_tokens SET username=?,status='approved' WHERE token=?",
            (st.session_state["user"],token)
            )

            conn.commit()

            st.success("Login approved")
            st.stop()

# --------------------
# REGISTER
# --------------------

def register():

    st.title("Register")

    u=st.text_input("Username")
    p=st.text_input("Password",type="password")

    if st.button("Register"):

        c.execute(
        "INSERT INTO users(username,password) VALUES(?,?)",
        (u,hash_text(p))
        )

        conn.commit()

        st.success("Account created")

# --------------------
# LOGIN
# --------------------

def login():

    st.title("Login")

    u=st.text_input("Username")
    p=st.text_input("Password",type="password")

    if st.button("Login"):

        c.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (u,hash_text(p))
        )

        if c.fetchone():

            st.session_state["user"]=u
            st.success("Logged in")
            st.rerun()

        else:
            st.error("Invalid login")

# --------------------
# LOGOUT
# --------------------

def logout():

    if st.sidebar.button("Logout"):

        st.session_state.clear()
        st.rerun()

# --------------------
# LINK DEVICE
# --------------------

def link_device():

    st.header("Link Device")

    if st.button("Link this device"):

        c.execute(
        "INSERT INTO devices VALUES(?,?)",
        (st.session_state["user"],device_hash())
        )

        conn.commit()

        st.success("Device linked")

# --------------------
# UNLINK DEVICE
# --------------------

def unlink_device():

    st.header("Unlink Device")

    if st.button("Unlink this device"):

        c.execute(
        "DELETE FROM devices WHERE username=? AND device_hash=?",
        (st.session_state["user"],device_hash())
        )

        conn.commit()

        st.success("Device removed")

# --------------------
# QR LOGIN (LAPTOP)
# --------------------

def qr_login():

    st.title("QR Login")

    token=str(uuid.uuid4())

    c.execute(
    "INSERT INTO qr_tokens(token,username,status) VALUES(?,?,?)",
    (token,"","pending")
    )

    conn.commit()

    base_url=st.secrets.get("APP_URL","http://localhost:8501")

    url=f"{base_url}/?qr_token={token}"

    qr=qrcode.make(url)

    buf=BytesIO()
    qr.save(buf)

    st.image(buf.getvalue())

    st.write("Scan with your logged-in device")

    if st.button("Check Status"):

        c.execute(
        "SELECT username,status FROM qr_tokens WHERE token=?",
        (token,)
        )

        row=c.fetchone()

        if row and row[1]=="approved":

            st.session_state["user"]=row[0]
            st.success("Logged in successfully")
            st.rerun()

        else:
            st.warning("Waiting for approval")

# --------------------
# DASHBOARD
# --------------------

def dashboard():

    st.title("ML Security Dashboard")

    device=device_hash()
    ip="127.0.0.1"

    score,status=predict_risk(device,ip,datetime.now().hour)

    st.metric("Risk Score",score)
    st.metric("Status",status)

    st.subheader("Trusted Devices")

    c.execute(
    "SELECT device_hash FROM devices WHERE username=?",
    (st.session_state["user"],)
    )

    for d in c.fetchall():
        st.code(d[0][:20])

# --------------------
# MENU
# --------------------

if "user" not in st.session_state:

    menu=st.sidebar.selectbox("Menu",["Login","Register","QR Login"])

    if menu=="Login":
        login()

    if menu=="Register":
        register()

    if menu=="QR Login":
        qr_login()

else:

    logout()

    page=st.sidebar.selectbox(
    "Dashboard",
    ["Dashboard","Link Device","Unlink Device"]
    )

    if page=="Dashboard":
        dashboard()

    if page=="Link Device":
        link_device()

    if page=="Unlink Device":
        unlink_device()
