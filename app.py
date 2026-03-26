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

# =========================================================
# CONFIG
# =========================================================
st.set_page_config(page_title="ML QR Authentication", layout="wide")

# IMPORTANT:
# Replace with your actual deployed Streamlit URL
APP_URL = "https://your-app-name.streamlit.app"

DB_NAME = "auth_ml.db"

# =========================================================
# DATABASE
# =========================================================
conn = sqlite3.connect(DB_NAME, check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    device_hash TEXT NOT NULL,
    device_name TEXT,
    trusted INTEGER DEFAULT 1,
    created_at TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS login_requests(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_token TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    requester_device_hash TEXT NOT NULL,
    status TEXT NOT NULL,
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

# =========================================================
# HELPERS
# =========================================================
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def get_device_hash() -> str:
    """
    Simulated device fingerprint for Streamlit session/browser.
    In real production, device fingerprinting would be stronger.
    """
    if "device_id" not in st.session_state:
        st.session_state["device_id"] = str(uuid.uuid4())
    return hash_text(st.session_state["device_id"])

def default_device_name() -> str:
    if "device_name" not in st.session_state:
        st.session_state["device_name"] = f"Device-{str(uuid.uuid4())[:8]}"
    return st.session_state["device_name"]

def user_exists(username: str) -> bool:
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    return c.fetchone() is not None

def register_user(username: str, password: str) -> bool:
    try:
        c.execute(
            "INSERT INTO users(username, password, created_at) VALUES (?, ?, ?)",
            (username, hash_text(password), now_str())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(username: str, password: str) -> bool:
    c.execute(
        "SELECT id FROM users WHERE username=? AND password=?",
        (username, hash_text(password))
    )
    return c.fetchone() is not None

def add_trusted_device(username: str, device_hash: str, device_name: str) -> None:
    c.execute(
        "SELECT id FROM devices WHERE username=? AND device_hash=?",
        (username, device_hash)
    )
    existing = c.fetchone()

    if existing is None:
        c.execute("""
            INSERT INTO devices(username, device_hash, device_name, trusted, created_at)
            VALUES (?, ?, ?, 1, ?)
        """, (username, device_hash, device_name, now_str()))
        conn.commit()
    else:
        c.execute("""
            UPDATE devices
            SET trusted=1, device_name=?
            WHERE username=? AND device_hash=?
        """, (device_name, username, device_hash))
        conn.commit()

def is_trusted_device(username: str, device_hash: str) -> bool:
    c.execute("""
        SELECT id FROM devices
        WHERE username=? AND device_hash=? AND trusted=1
    """, (username, device_hash))
    return c.fetchone() is not None

def get_user_devices(username: str):
    c.execute("""
        SELECT device_hash, device_name, trusted, created_at
        FROM devices
        WHERE username=?
        ORDER BY id DESC
    """, (username,))
    return c.fetchall()

def remove_device(username: str, device_hash: str) -> None:
    c.execute("""
        DELETE FROM devices
        WHERE username=? AND device_hash=?
    """, (username, device_hash))
    conn.commit()

def create_login_request(username: str, requester_device_hash: str) -> str:
    token = str(uuid.uuid4())
    c.execute("""
        INSERT INTO login_requests(request_token, username, requester_device_hash, status, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token, username, requester_device_hash, "pending", now_str()))
    conn.commit()
    return token

def get_login_request(token: str):
    c.execute("""
        SELECT id, request_token, username, requester_device_hash, status, created_at
        FROM login_requests
        WHERE request_token=?
    """, (token,))
    return c.fetchone()

def update_login_request_status(token: str, status: str) -> None:
    c.execute("""
        UPDATE login_requests
        SET status=?
        WHERE request_token=?
    """, (status, token))
    conn.commit()

def get_recent_login_requests(username: str):
    c.execute("""
        SELECT request_token, status, created_at
        FROM login_requests
        WHERE username=?
        ORDER BY id DESC
        LIMIT 10
    """, (username,))
    return c.fetchall()

def save_login_log(username, login_hour, failed_attempts, new_device, distance_km, trusted_device, risk_result):
    c.execute("""
        INSERT INTO login_logs(
            username, login_hour, failed_attempts, new_device,
            distance_km, trusted_device, risk_result, timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, login_hour, failed_attempts, new_device,
        distance_km, trusted_device, risk_result, now_str()
    ))
    conn.commit()

def get_logs():
    c.execute("""
        SELECT username, login_hour, failed_attempts, new_device,
               distance_km, trusted_device, risk_result, timestamp
        FROM login_logs
        ORDER BY id DESC
    """)
    return c.fetchall()

# =========================================================
# MACHINE LEARNING
# =========================================================
@st.cache_resource
def train_model():
    data = []
    labels = []

    # Synthetic training data
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
            label = 0   # Low Risk
        elif score <= 4:
            label = 1   # Medium Risk
        else:
            label = 2   # High Risk

        data.append([login_hour, failed_attempts, new_device, distance_km, trusted_device])
        labels.append(label)

    X = pd.DataFrame(
        data,
        columns=["login_hour", "failed_attempts", "new_device", "distance_km", "trusted_device"]
    )
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=120, random_state=42)
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

    mapping = {
        0: "Low Risk",
        1: "Medium Risk",
        2: "High Risk"
    }
    return mapping[pred], proba

# =========================================================
# SESSION STATE
# =========================================================
if "user" not in st.session_state:
    st.session_state["user"] = None

if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

if "page" not in st.session_state:
    st.session_state["page"] = "Home"

# =========================================================
# QUERY PARAM AUTO-DETECTION
# =========================================================
query_params = st.query_params

if "approve_token" in query_params:
    st.session_state["approve_token"] = query_params["approve_token"]
    st.session_state["page"] = "Approve QR"

# =========================================================
# SIDEBAR
# =========================================================
pages = ["Home", "Register", "Login", "Dashboard", "Approve QR", "Admin Logs"]

current_page = st.session_state.get("page", "Home")
if current_page not in pages:
    current_page = "Home"

menu = st.sidebar.radio(
    "Navigation",
    pages,
    index=pages.index(current_page)
)

st.session_state["page"] = menu

st.sidebar.markdown("---")
st.sidebar.write(f"**Current Device Name:** {default_device_name()}")
st.sidebar.caption(f"Hash: {get_device_hash()[:20]}...")

# =========================================================
# HOME
# =========================================================
if menu == "Home":
    st.title("Integration of Machine Learning in QR Code Authentication System")
    st.write("""
This system uses:

- **Username and password**
- **Trusted devices**
- **QR code approval for new devices**
- **Machine learning risk analysis**
- **SQLite database**
- **Python + Streamlit in one file**
""")

    st.info("""
Flow:
1. User logs in with username and password.
2. If the device is trusted, login is allowed immediately.
3. If the device is new, the app generates a QR code.
4. A trusted device scans the QR code to approve the login.
5. After approval, the new device is automatically linked as trusted.
""")

# =========================================================
# REGISTER
# =========================================================
elif menu == "Register":
    st.title("Register")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    device_name = st.text_input("Device Name", value=default_device_name())

    if st.button("Create Account"):
        username = username.strip()
        password = password.strip()
        device_name = device_name.strip() or default_device_name()

        if not username or not password:
            st.error("Please fill in all fields.")
        elif user_exists(username):
            st.error("Username already exists.")
        else:
            ok = register_user(username, password)
            if ok:
                add_trusted_device(username, get_device_hash(), device_name)
                st.success("Account created successfully.")
                st.info("This registration device has been added as the first trusted device.")
            else:
                st.error("Registration failed.")

# =========================================================
# LOGIN
# =========================================================
elif menu == "Login":
    st.title("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    device_name = st.text_input("Current Device Name", value=default_device_name(), key="login_device_name")

    if st.button("Login"):
        username = username.strip()
        password = password.strip()
        device_name = device_name.strip() or default_device_name()

        if not username or not password:
            st.error("Please fill in all fields.")
        elif not verify_user(username, password):
            st.session_state["failed_attempts"] += 1
            st.error("Invalid username or password.")
        else:
            current_device = get_device_hash()

            if is_trusted_device(username, current_device):
                st.session_state["user"] = username
                st.session_state["failed_attempts"] = 0
                add_trusted_device(username, current_device, device_name)
                st.success("Login successful on trusted device.")
            else:
                request_token = create_login_request(username, current_device)
                approve_link = f"{APP_URL}/?approve_token={request_token}"

                qr = qrcode.make(approve_link)
                buf = BytesIO()
                qr.save(buf, format="PNG")

                st.session_state["pending_request_token"] = request_token
                st.session_state["pending_request_username"] = username
                st.session_state["pending_new_device_name"] = device_name

                st.warning("This device is not trusted.")
                st.info("Scan the QR code with a trusted device to approve the login.")
                st.image(buf.getvalue(), caption="Scan with a trusted device")
                st.code(approve_link, language="text")

    # Waiting state after QR has been generated
    if "pending_request_token" in st.session_state:
        st.markdown("---")
        st.subheader("Pending Login Request")
        st.write(f"**Username:** {st.session_state.get('pending_request_username', '')}")
        st.write(f"**Request Token:** {st.session_state['pending_request_token']}")

        req = get_login_request(st.session_state["pending_request_token"])
        if req:
            _, _, _, _, status, created_at = req
            st.write(f"**Status:** {status}")
            st.caption(f"Created: {created_at}")

        if st.button("I've been approved, continue login"):
            req = get_login_request(st.session_state["pending_request_token"])

            if not req:
                st.error("Login request not found.")
            else:
                _, _, username_req, _, status, _ = req

                if status == "approved":
                    st.session_state["user"] = username_req
                    st.session_state["failed_attempts"] = 0
                    add_trusted_device(
                        username_req,
                        get_device_hash(),
                        st.session_state.get("pending_new_device_name", default_device_name())
                    )

                    del st.session_state["pending_request_token"]
                    del st.session_state["pending_request_username"]
                    del st.session_state["pending_new_device_name"]

                    st.success("Login successful. This new device is now linked as trusted.")
                    st.rerun()

                elif status == "blocked":
                    st.error("This login request was blocked.")
                else:
                    st.info("Approval is still pending.")

# =========================================================
# DASHBOARD
# =========================================================
elif menu == "Dashboard":
    st.title("Dashboard")

    if not st.session_state["user"]:
        st.warning("Please log in first.")
    else:
        username = st.session_state["user"]
        st.success(f"Logged in as: {username}")

        st.subheader("Trusted Devices")
        devices = get_user_devices(username)

        if devices:
            current_hash = get_device_hash()
            for d_hash, d_name, trusted, created_at in devices:
                col1, col2 = st.columns([5, 1])

                with col1:
                    marker = " (Current Device)" if d_hash == current_hash else ""
                    st.write(f"**{d_name}{marker}**")
                    st.caption(f"Trusted: {'Yes' if trusted else 'No'} | Added: {created_at}")
                    st.caption(f"Hash: {d_hash[:24]}...")

                with col2:
                    if d_hash != current_hash:
                        if st.button("Unlink", key=f"unlink_{d_hash}"):
                            remove_device(username, d_hash)
                            st.success("Device unlinked.")
                            st.rerun()
        else:
            st.info("No devices linked.")

        st.markdown("---")
        st.subheader("Recent Login Requests")
        recent_requests = get_recent_login_requests(username)
        if recent_requests:
            req_df = pd.DataFrame(recent_requests, columns=["Request Token", "Status", "Created At"])
            st.dataframe(req_df, use_container_width=True)
        else:
            st.info("No login requests found.")

        st.markdown("---")
        if st.button("Logout"):
            st.session_state["user"] = None
            st.success("Logged out.")
            st.rerun()

# =========================================================
# APPROVE QR
# =========================================================
elif menu == "Approve QR":
    st.title("Approve Login Request")

    token_default = st.session_state.get("approve_token", "")
    token = st.text_input("Approval Token", value=token_default)

    if token:
        req = get_login_request(token)

        if not req:
            st.error("Invalid or missing login request.")
        else:
            _, request_token, username, requester_device_hash, status, created_at = req

            st.write(f"**Username:** {username}")
            st.write(f"**Status:** {status}")
            st.caption(f"Created: {created_at}")

            current_device = get_device_hash()
            trusted = is_trusted_device(username, current_device)

            if status != "pending":
                st.warning(f"This request is already {status}.")
            elif not trusted:
                st.error("This device is not trusted for this account, so it cannot approve the login.")
            else:
                # Simulated login context for ML
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

                st.subheader("Machine Learning Risk Analysis")
                st.write(f"**Login Hour:** {login_hour}")
                st.write(f"**Failed Attempts:** {failed_attempts}")
                st.write(f"**New Device:** Yes")
                st.write(f"**Distance (km):** {distance_km:.2f}")
                st.write(f"**Trusted Approver Device:** Yes")
                st.write(f"### Prediction: {risk_label}")

                prob_df = pd.DataFrame({
                    "Risk Level": ["Low Risk", "Medium Risk", "High Risk"],
                    "Probability": [
                        round(float(proba[0]), 4),
                        round(float(proba[1]), 4),
                        round(float(proba[2]), 4)
                    ]
                })
                st.dataframe(prob_df, use_container_width=True)

                col1, col2 = st.columns(2)

                with col1:
                    if risk_label == "High Risk":
                        st.warning("High-risk login detected. Approval is discouraged.")
                    else:
                        if st.button("Approve Login"):
                            update_login_request_status(token, "approved")
                            save_login_log(
                                username,
                                login_hour,
                                failed_attempts,
                                new_device,
                                distance_km,
                                trusted_device,
                                risk_label
                            )
                            st.success("Login approved. The waiting device can now complete login.")

                with col2:
                    if st.button("Block Login"):
                        update_login_request_status(token, "blocked")
                        save_login_log(
                            username,
                            login_hour,
                            failed_attempts,
                            new_device,
                            distance_km,
                            trusted_device,
                            "Blocked"
                        )
                        st.error("Login blocked.")

# =========================================================
# ADMIN LOGS
# =========================================================
elif menu == "Admin Logs":
    st.title("Authentication Logs")

    rows = get_logs()
    if rows:
        df = pd.DataFrame(rows, columns=[
            "Username",
            "Login Hour",
            "Failed Attempts",
            "New Device",
            "Distance (km)",
            "Trusted Device",
            "Risk Result",
            "Timestamp"
        ])
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No logs yet.")
