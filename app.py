import streamlit as st
import sqlite3
import hashlib
import uuid
import qrcode
from io import BytesIO
from datetime import datetime
import random
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="ML QR Authentication System", layout="wide")

# =========================
# DATABASE
# =========================
conn = sqlite3.connect("auth_ml.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    device_hash TEXT,
    device_name TEXT,
    trusted INTEGER DEFAULT 0
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS qr_tokens(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    username TEXT,
    status TEXT,
    created_at TEXT
)
""")

c.execute("""
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

conn.commit()

# =========================
# HELPERS
# =========================
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_device_hash():
    # Simulated device fingerprint
    if "device_id" not in st.session_state:
        st.session_state.device_id = str(uuid.uuid4())
    return hash_text(st.session_state.device_id)

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def user_exists(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return c.fetchone()

def verify_user(username, password):
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_text(password)))
    return c.fetchone()

def register_user(username, password):
    try:
        c.execute("INSERT INTO users(username, password) VALUES (?, ?)", (username, hash_text(password)))
        conn.commit()
        return True
    except:
        return False

def add_trusted_device(username, device_hash, device_name="Current Device"):
    c.execute("SELECT * FROM devices WHERE username=? AND device_hash=?", (username, device_hash))
    if not c.fetchone():
        c.execute("""
            INSERT INTO devices(username, device_hash, device_name, trusted)
            VALUES (?, ?, ?, 1)
        """, (username, device_hash, device_name))
        conn.commit()

def is_trusted_device(username, device_hash):
    c.execute("""
        SELECT * FROM devices WHERE username=? AND device_hash=? AND trusted=1
    """, (username, device_hash))
    return c.fetchone() is not None

def get_user_devices(username):
    c.execute("SELECT device_hash, device_name, trusted FROM devices WHERE username=?", (username,))
    return c.fetchall()

def remove_device(username, device_hash):
    c.execute("DELETE FROM devices WHERE username=? AND device_hash=?", (username, device_hash))
    conn.commit()

def create_qr_token(username):
    token = str(uuid.uuid4())
    c.execute("""
        INSERT INTO qr_tokens(token, username, status, created_at)
        VALUES (?, ?, ?, ?)
    """, (token, username, "pending", current_time()))
    conn.commit()
    return token

def get_qr_token(token):
    c.execute("SELECT * FROM qr_tokens WHERE token=?", (token,))
    return c.fetchone()

def update_qr_status(token, status):
    c.execute("UPDATE qr_tokens SET status=? WHERE token=?", (status, token))
    conn.commit()

def save_login_log(username, login_hour, failed_attempts, new_device, distance_km, trusted_device, risk_result):
    c.execute("""
        INSERT INTO login_logs(username, login_hour, failed_attempts, new_device, distance_km, trusted_device, risk_result, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, login_hour, failed_attempts, new_device,
        distance_km, trusted_device, risk_result, current_time()
    ))
    conn.commit()

# =========================
# ML MODEL
# =========================
@st.cache_resource
def train_model():
    # Synthetic dataset
    data = []
    labels = []

    for _ in range(1000):
        login_hour = random.randint(0, 23)
        failed_attempts = random.randint(0, 6)
        new_device = random.randint(0, 1)
        distance_km = random.uniform(0, 5000)
        trusted_device = random.randint(0, 1)

        # Simple rule to generate labels
        risk_score = 0
        if login_hour < 5 or login_hour > 22:
            risk_score += 1
        if failed_attempts >= 3:
            risk_score += 2
        if new_device == 1:
            risk_score += 2
        if distance_km > 1000:
            risk_score += 2
        if trusted_device == 0:
            risk_score += 1

        if risk_score <= 2:
            label = 0   # low risk
        elif risk_score <= 4:
            label = 1   # medium risk
        else:
            label = 2   # high risk

        data.append([login_hour, failed_attempts, new_device, distance_km, trusted_device])
        labels.append(label)

    X = pd.DataFrame(data, columns=[
        "login_hour", "failed_attempts", "new_device", "distance_km", "trusted_device"
    ])
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

model = train_model()

def predict_risk(login_hour, failed_attempts, new_device, distance_km, trusted_device):
    X = pd.DataFrame([[
        login_hour, failed_attempts, new_device, distance_km, trusted_device
    ]], columns=[
        "login_hour", "failed_attempts", "new_device", "distance_km", "trusted_device"
    ])
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    mapping = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}
    return mapping[pred], proba

# =========================
# SESSION STATE
# =========================
if "user" not in st.session_state:
    st.session_state.user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# =========================
# SIDEBAR
# =========================
st.sidebar.title("ML QR Authentication")
menu = st.sidebar.radio("Navigation", [
    "Home", "Register", "Login", "Dashboard", "QR Login", "Approve QR", "Admin Logs"
])

# =========================
# HOME
# =========================
if menu == "Home":
    st.title("Integration of Machine Learning in QR Code Authentication System")
    st.write("""
    This system combines:
    - **QR code authentication**
    - **Machine learning risk analysis**
    - **Trusted device management**
    - **Streamlit user interface**
    - **SQLite database**
    
    The ML model checks whether a login attempt is normal or suspicious before access is granted.
    """)

# =========================
# REGISTER
# =========================
elif menu == "Register":
    st.title("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Create Account"):
        if not username or not password:
            st.error("Fill in all fields.")
        elif user_exists(username):
            st.error("Username already exists.")
        else:
            if register_user(username, password):
                device_hash = get_device_hash()
                add_trusted_device(username, device_hash, "Registered Device")
                st.success("Account created successfully.")
                st.info("This device has been automatically added as a trusted device.")
            else:
                st.error("Registration failed.")

# =========================
# LOGIN
# =========================
elif menu == "Login":
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = verify_user(username, password)
        if user:
            st.session_state.user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome, {username}")
        else:
            st.session_state.failed_attempts += 1
            st.error("Invalid username or password.")

# =========================
# DASHBOARD
# =========================
elif menu == "Dashboard":
    st.title("Dashboard")

    if not st.session_state.user:
        st.warning("Please log in first.")
    else:
        username = st.session_state.user
        st.success(f"Logged in as: {username}")

        st.subheader("Trusted Devices")
        devices = get_user_devices(username)

        if devices:
            for d_hash, d_name, trusted in devices:
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.write(f"**{d_name}**")
                    st.caption(f"Hash: {d_hash[:18]}... | Trusted: {'Yes' if trusted else 'No'}")
                with col2:
                    if st.button("Remove", key=f"remove_{d_hash}"):
                        remove_device(username, d_hash)
                        st.success("Device removed.")
                        st.rerun()
        else:
            st.info("No linked devices.")

        st.subheader("Link Current Device")
        device_name = st.text_input("Device Name", value="My Device")
        if st.button("Trust This Device"):
            add_trusted_device(username, get_device_hash(), device_name)
            st.success("Current device added as trusted.")
            st.rerun()

        if st.button("Logout"):
            st.session_state.user = None
            st.success("Logged out.")

# =========================
# QR LOGIN
# =========================
elif menu == "QR Login":
    st.title("QR Login")

    username = st.text_input("Enter username for QR login")

    if st.button("Generate QR Login Code"):
        if not user_exists(username):
            st.error("User does not exist.")
        else:
            token = create_qr_token(username)

            # In real deployment, this would be a URL
            qr_data = f"LOGIN_TOKEN:{token}"

            qr = qrcode.make(qr_data)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            st.image(buf.getvalue(), caption="Scan this QR code with a trusted device")

            st.code(qr_data, language="text")
            st.info("For testing, copy the token and use the 'Approve QR' page.")

# =========================
# APPROVE QR
# =========================
elif menu == "Approve QR":
    st.title("Approve QR Login")

    token_input = st.text_input("Paste scanned QR token here")

    if st.button("Check Token"):
        if not token_input.startswith("LOGIN_TOKEN:"):
            st.error("Invalid token format.")
        else:
            token = token_input.replace("LOGIN_TOKEN:", "").strip()
            record = get_qr_token(token)

            if not record:
                st.error("Token not found.")
            else:
                _, token_value, username, status, created_at = record

                if status != "pending":
                    st.warning(f"This token is already {status}.")
                else:
                    device_hash = get_device_hash()
                    trusted = is_trusted_device(username, device_hash)

                    # Simulated login context
                    login_hour = datetime.now().hour
                    failed_attempts = st.session_state.failed_attempts
                    new_device = 0 if trusted else 1
                    distance_km = random.uniform(1, 4000)  # simulate geo distance
                    trusted_device = 1 if trusted else 0

                    risk_label, proba = predict_risk(
                        login_hour, failed_attempts, new_device, distance_km, trusted_device
                    )

                    st.subheader("Risk Analysis")
                    st.write(f"**Username:** {username}")
                    st.write(f"**Login Hour:** {login_hour}")
                    st.write(f"**Failed Attempts:** {failed_attempts}")
                    st.write(f"**New Device:** {'Yes' if new_device else 'No'}")
                    st.write(f"**Distance (km):** {distance_km:.2f}")
                    st.write(f"**Trusted Device:** {'Yes' if trusted_device else 'No'}")
                    st.write(f"### Prediction: {risk_label}")

                    st.write("**Prediction Probabilities:**")
                    st.write({
                        "Low Risk": round(proba[0], 3),
                        "Medium Risk": round(proba[1], 3),
                        "High Risk": round(proba[2], 3)
                    })

                    save_login_log(
                        username, login_hour, failed_attempts,
                        new_device, distance_km, trusted_device, risk_label
                    )

                    if risk_label == "Low Risk":
                        update_qr_status(token, "approved")
                        st.success("Login approved automatically.")
                        st.session_state.user = username

                    elif risk_label == "Medium Risk":
                        if trusted:
                            update_qr_status(token, "approved")
                            st.success("Medium risk, but trusted device. Login approved.")
                            st.session_state.user = username
                        else:
                            update_qr_status(token, "blocked")
                            st.warning("Medium risk from untrusted device. Login blocked.")

                    else:
                        update_qr_status(token, "blocked")
                        st.error("High-risk login attempt blocked.")

# =========================
# ADMIN LOGS
# =========================
elif menu == "Admin Logs":
    st.title("Authentication Logs")

    c.execute("""
        SELECT username, login_hour, failed_attempts, new_device, distance_km,
               trusted_device, risk_result, timestamp
        FROM login_logs
        ORDER BY id DESC
    """)
    rows = c.fetchall()

    if rows:
        df = pd.DataFrame(rows, columns=[
            "Username", "Login Hour", "Failed Attempts", "New Device",
            "Distance (km)", "Trusted Device", "Risk Result", "Timestamp"
        ])
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No logs yet.")
