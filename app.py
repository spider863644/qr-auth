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
        st.session_state["_cookies_cache"] = cookie_manager.get_all(key="main_cookie_load")
    return st.session_state["_cookies_cache"]


def clear_cookie_cache():
    st.session_state["_cookies_cache"] = {}


def safe_delete_cookie(cookie_name: str):
    cookies = load_cookies_once()
    if cookies.get(cookie_name) is not None:
        try:
            cookie_manager.delete(cookie_name)
        except Exception:
            pass

    if "_cookies_cache" not in st.session_state:
        st.session_state["_cookies_cache"] = {}

    st.session_state["_cookies_cache"].pop(cookie_name, None)


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
    requested_username TEXT,
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
# MIGRATIONS
# =========================================================
def column_exists(table_name, column_name):
    c.execute(f"PRAGMA table_info({table_name})")
    cols = [row[1] for row in c.fetchall()]
    return column_name in cols


def ensure_devices_unique_constraint():
    c.execute("PRAGMA index_list(devices)")
    indexes = c.fetchall()

    has_unique = False
    for idx in indexes:
        if len(idx) > 2 and idx[2] == 1:
            has_unique = True
            break

    if not has_unique:
        c.execute("""
        CREATE TABLE IF NOT EXISTS devices_new(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            UNIQUE(username, device_hash)
        )
        """)

        c.execute("""
        INSERT OR IGNORE INTO devices_new(username, device_hash)
        SELECT username, device_hash FROM devices
        """)

        c.execute("DROP TABLE devices")
        c.execute("ALTER TABLE devices_new RENAME TO devices")
        conn.commit()


ensure_devices_unique_constraint()

if not column_exists("qr_tokens", "requested_username"):
    c.execute("ALTER TABLE qr_tokens ADD COLUMN requested_username TEXT")
    conn.commit()

# =========================================================
# HELPERS
# =========================================================
def now_iso() -> str:
    return datetime.now().isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def get_or_create_device_id():
    cookies = load_cookies_once()
    device_id = cookies.get("device_id")

    if not device_id:
        device_id = str(uuid.uuid4())
        cookie_manager.set("device_id", device_id)

        if "_cookies_cache" not in st.session_state:
            st.session_state["_cookies_cache"] = {}

        st.session_state["_cookies_cache"]["device_id"] = device_id

    return device_id


def device_hash() -> str:
    return hash_text(get_or_create_device_id())


def predict_risk(device: str, ip: str, hour: int):
    score = random.uniform(0, 1)
    if score < 0.4:
        status = "Safe"
    elif score < 0.7:
        status = "Suspicious"
    else:
        status = "High Risk"
    return round(score, 2), status


def is_device_linked(username: str, device_hash_value: str) -> bool:
    c.execute(
        "SELECT 1 FROM devices WHERE username=? AND device_hash=?",
        (username, device_hash_value)
    )
    return c.fetchone() is not None


# =========================================================
# CLEANUP
# =========================================================
def cleanup_old_entries():
    now = datetime.now()

    c.execute("SELECT session_id, created_at FROM sessions")
    for session_id, created_at in c.fetchall():
        try:
            if now - parse_iso(created_at) > timedelta(hours=SESSION_HOURS):
                c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        except Exception:
            c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))

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

    if "_cookies_cache" not in st.session_state:
        st.session_state["_cookies_cache"] = {}

    st.session_state["_cookies_cache"]["user_session"] = session_id
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
        safe_delete_cookie("user_session")
        return None

    username, created_at = row

    try:
        created_dt = parse_iso(created_at)
    except Exception:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        safe_delete_cookie("user_session")
        clear_cookie_cache()
        return None

    if datetime.now() - created_dt > timedelta(hours=SESSION_HOURS):
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        safe_delete_cookie("user_session")
        clear_cookie_cache()
        return None

    return username


def logout_user():
    session_id = get_cookie_session_id()
    if session_id:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()

    existing_device_id = None
    cookies = load_cookies_once()
    if cookies.get("device_id"):
        existing_device_id = cookies.get("device_id")

    safe_delete_cookie("user_session")
    clear_cookie_cache()

    if existing_device_id:
        st.session_state["_cookies_cache"]["device_id"] = existing_device_id

    for key in list(st.session_state.keys()):
        if key != "_cookies_cache":
            del st.session_state[key]

    st.rerun()


existing_user = get_session_user()
if existing_user:
    st.session_state["user"] = existing_user

# =========================================================
# QR TOKEN HELPERS
# =========================================================
def create_qr_token(requested_username: str = ""):
    token = str(uuid.uuid4())
    c.execute(
        """
        INSERT INTO qr_tokens(token, username, requested_username, status, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (token, "", requested_username, "pending", now_iso())
    )
    conn.commit()
    return token


def get_qr_status(token: str):
    c.execute(
        """
        SELECT username, requested_username, status, created_at
        FROM qr_tokens
        WHERE token=?
        """,
        (token,)
    )
    return c.fetchone()


def approve_qr_token(token: str, approving_username: str):
    c.execute(
        """
        UPDATE qr_tokens
        SET username=?, status='approved'
        WHERE token=? AND status='pending'
        """,
        (approving_username, token)
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
# LOGIN HELPERS
# =========================================================
def start_new_device_qr_flow(username: str):
    token = create_qr_token(requested_username=username)
    st.session_state["qr_token"] = token
    st.session_state["pending_login_username"] = username
    return token


# =========================================================
# SHARED LOGIN FORM
# =========================================================
def login_form(title="Login", button_key="login_button", redirect_untrusted_to_qr=False):
    st.title(title)

    username = st.text_input("Username", key=f"{button_key}_username")
    password = st.text_input("Password", type="password", key=f"{button_key}_password")

    if st.button("Login", key=button_key, use_container_width=True):
        username = username.strip()

        c.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (username, hash_text(password))
        )
        user = c.fetchone()

        if not user:
            st.error("Invalid username or password.")
            return False

        current_hash = device_hash()

        if redirect_untrusted_to_qr and not is_device_linked(username, current_hash):
            start_new_device_qr_flow(username)
            st.warning("This device is not trusted. Approval from a linked device is required.")
            time.sleep(0.7)
            st.rerun()

        create_session(username)
        st.success("Logged in successfully.")
        time.sleep(0.5)
        return True

    return False


# =========================================================
# REGISTER PAGE
# =========================================================
def register():
    st.title("Register")

    username = st.text_input("Username", key="register_username")
    password = st.text_input("Password", type="password", key="register_password")

    if st.button("Register", key="register_button", use_container_width=True):
        username = username.strip()

        if not username or not password:
            st.error("Username and password are required.")
            return

        try:
            c.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (username, hash_text(password))
            )
            conn.commit()
            st.success("Account created successfully.")
        except sqlite3.IntegrityError:
            st.error("Username already exists.")


# =========================================================
# NORMAL LOGIN PAGE
# =========================================================
def login():
    success = login_form(
        title="Login",
        button_key="main_login_button",
        redirect_untrusted_to_qr=True
    )
    if success:
        st.rerun()


# =========================================================
# QR APPROVAL PAGE
# STRICT MODE: only linked device belonging to requested user
# =========================================================
def qr_approval_page(token: str):
    st.title("Approve QR Login")

    row = get_qr_status(token)
    if not row:
        st.error("This QR request does not exist or has expired.")
        st.stop()

    approved_username, requested_username, status, created_at = row

    if qr_is_expired(created_at):
        delete_qr_token(token)
        st.error("This QR code has expired.")
        st.stop()

    created_dt = parse_iso(created_at)
    remaining = timedelta(minutes=QR_MINUTES) - (datetime.now() - created_dt)
    seconds_left = max(0, int(remaining.total_seconds()))
    st.caption(f"QR expires in about {seconds_left} seconds.")

    approving_user = get_session_user()

    if not approving_user:
        st.info("Log in on this page to approve the QR login.")
        success = login_form(
            title="Login to Approve",
            button_key="qr_approval_login_button",
            redirect_untrusted_to_qr=False
        )
        if success:
            st.rerun()
        st.stop()

    current_hash = device_hash()

    # Strict mode rule 1: approver must be the same account being requested
    if requested_username and approving_user != requested_username:
        st.error("Only the same user account can approve this login.")
        st.info(f"This login request is for: {requested_username}")
        st.stop()

    # Strict mode rule 2: approver device must be linked/trusted
    if not is_device_linked(approving_user, current_hash):
        st.error("This device is not trusted and cannot approve QR login.")
        st.info("Use one of your linked devices to approve this login.")
        st.stop()

    st.success(f"Logged in as: {approving_user}")
    st.info("This is a trusted device.")

    if status == "approved":
        st.info(f"This login has already been approved for {approved_username}.")
        st.stop()

    if st.button("Approve Login", key="approve_qr_button", use_container_width=True):
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

    if st.button("Link this device", key="link_device_button", use_container_width=True):
        c.execute(
            "SELECT id FROM devices WHERE username=? AND device_hash=?",
            (current_user, current_hash)
        )
        exists = c.fetchone()

        if exists:
            st.warning("This device is already linked to your account.")
        else:
            try:
                c.execute(
                    "INSERT INTO devices(username, device_hash) VALUES (?, ?)",
                    (current_user, current_hash)
                )
                conn.commit()
                st.success("Device linked successfully.")
            except sqlite3.IntegrityError:
                st.warning("This device is already linked to your account.")


def unlink_device():
    st.subheader("Unlink Device")
    current_user = st.session_state["user"]
    current_hash = device_hash()

    if st.button("Unlink this device", key="unlink_device_button", use_container_width=True):
        c.execute(
            "SELECT id FROM devices WHERE username=? AND device_hash=?",
            (current_user, current_hash)
        )
        exists = c.fetchone()

        if not exists:
            st.warning("This device is not currently linked.")
        else:
            c.execute(
                "DELETE FROM devices WHERE username=? AND device_hash=?",
                (current_user, current_hash)
            )
            conn.commit()
            st.success("Device removed.")


# =========================================================
# QR LOGIN PAGE (PC / NEW DEVICE)
# =========================================================
def qr_login():
    st.title("QR Login")

    if "qr_token" not in st.session_state:
        st.session_state["qr_token"] = create_qr_token()

    token = st.session_state["qr_token"]

    row = get_qr_status(token)
    if not row:
        requested_username = st.session_state.get("pending_login_username", "")
        st.session_state["qr_token"] = create_qr_token(requested_username=requested_username)
        token = st.session_state["qr_token"]
        row = get_qr_status(token)

    approved_username, requested_username, status, created_at = row

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

    st.image(buf.getvalue(), caption="Scan this with your trusted linked device", use_container_width=False)

    if requested_username:
        st.info(f"Pending login for: {requested_username}")

    created_dt = parse_iso(created_at)
    remaining = timedelta(minutes=QR_MINUTES) - (datetime.now() - created_dt)
    seconds_left = max(0, int(remaining.total_seconds()))
    minutes = seconds_left // 60
    seconds = seconds_left % 60

    st.caption(f"Expires in {minutes:02d}:{seconds:02d}")

    if status == "approved" and approved_username:
        # extra safety: approved account must match requested account
        if requested_username and approved_username != requested_username:
            st.error("Approval account mismatch. Login blocked.")
            delete_qr_token(token)
            if "qr_token" in st.session_state:
                del st.session_state["qr_token"]
            st.stop()

        create_session(approved_username)
        delete_qr_token(token)

        if "qr_token" in st.session_state:
            del st.session_state["qr_token"]
        if "pending_login_username" in st.session_state:
            del st.session_state["pending_login_username"]

        st.success(f"Logged in as {approved_username}.")
        time.sleep(0.8)
        st.rerun()
    else:
        st.warning("Waiting for approval from a trusted linked device...")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("Generate New QR", key="new_qr_button", use_container_width=True):
                delete_qr_token(token)
                requested_username = st.session_state.get("pending_login_username", "")
                st.session_state["qr_token"] = create_qr_token(requested_username=requested_username)
                st.rerun()

        with col2:
            st.link_button("Open approval link", qr_url, use_container_width=True)

        time.sleep(1)
        st.rerun()


# =========================================================
# DASHBOARD
# =========================================================
def dashboard():
    current_user = st.session_state["user"]

    st.title("ML Security Dashboard")
    st.write(f"Welcome, **{current_user}**")

    ip = "127.0.0.1"
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
    # if a new device login created a pending qr token, show qr page directly
    if "qr_token" in st.session_state and "pending_login_username" in st.session_state:
        qr_login()
    else:
        menu = st.sidebar.selectbox("Menu", ["Login", "Register", "QR Login"], key="main_menu")

        if menu == "Login":
            login()
        elif menu == "Register":
            register()
        elif menu == "QR Login":
            qr_login()
else:
    if st.sidebar.button("Logout", key="logout_button", use_container_width=True):
        logout_user()

    page = st.sidebar.selectbox(
        "Dashboard",
        ["Dashboard", "Link Device", "Unlink Device"],
        key="dashboard_menu"
    )

    if page == "Dashboard":
        dashboard()
    elif page == "Link Device":
        link_device()
    elif page == "Unlink Device":
        unlink_device()
