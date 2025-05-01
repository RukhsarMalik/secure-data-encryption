import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import time
import base64

USERS_FILE = "users.json"
DATA_FILE = "data.json"
ADMIN_PASSWORD = "admin123"
MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 30

# Session state
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True


# --- Utility Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_fernet(passkey: str) -> Fernet:
    key = hashlib.sha256(passkey.encode()).digest()  # 32-byte key
    key_b64 = base64.urlsafe_b64encode(key)  # Base64 encode it
    return Fernet(key_b64)

def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}


def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f)


# --- Auth Functions ---
def authenticate(username, password):
    users = load_json(USERS_FILE)
    return username in users and users[username] == hash_password(password)


def register_user(username, password):
    users = load_json(USERS_FILE)
    if username in users:
        return False
    users[username] = hash_password(password)
    save_json(USERS_FILE, users)
    return True


# --- Login Page ---
def login_page():
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate(username, password):
            st.success("Login successful!")
            st.session_state.user = username
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Login failed ({st.session_state.failed_attempts}/{MAX_ATTEMPTS})")
            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.session_state.lockout_time = time.time()
                st.session_state.authorized = False


# --- Register Page ---
def register_page():
    st.title("📝 Register")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")

    if st.button("Register"):
        if register_user(username, password):
            st.success("User registered! Please login.")
        else:
            st.error("Username already exists.")


# --- Home Page ---
def home_page():
    st.title("🏠 Welcome")
    st.write(f"Logged in as: `{st.session_state.user}`")

    option = st.radio("Select an option:", ["Insert Data", "Retrieve Data", "Logout"])

    if option == "Insert Data":
        insert_data_page()
    elif option == "Retrieve Data":
        retrieve_data_page()
    elif option == "Logout":
        st.session_state.user = None
        st.success("Logged out!")


# --- Insert Data ---
def insert_data_page():
    st.subheader("📥 Store Data")
    text = st.text_area("Enter text to store")
    passkey = st.text_input("Passkey (used for encryption)", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            fernet = get_fernet(passkey)
            encrypted = fernet.encrypt(text.encode()).decode()
            data = load_json(DATA_FILE)
            data[st.session_state.user] = {
                "encrypted_text": encrypted,
                "passkey_hash": hash_password(passkey),
            }
            save_json(DATA_FILE, data)
            st.success("Data stored securely.")
        else:
            st.warning("Please provide text and passkey.")


# --- Retrieve Data ---
def retrieve_data_page():
    st.subheader("🔓 Retrieve Data")

    if not st.session_state.authorized:
        st.warning("🔒 Too many failed attempts. Please reauthorize.")
        admin_auth_page()
        return

    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Decrypt"):
        data = load_json(DATA_FILE)
        user_data = data.get(st.session_state.user)

        if not user_data:
            st.error("No data found.")
            return

        if hash_password(passkey) == user_data["passkey_hash"]:
            fernet = get_fernet(passkey)
            decrypted = fernet.decrypt(user_data["encrypted_text"].encode()).decode()
            st.success("Data Decrypted:")
            st.code(decrypted)
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Incorrect passkey ({st.session_state.failed_attempts}/{MAX_ATTEMPTS})")
            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.session_state.lockout_time = time.time()
                st.session_state.authorized = False


# --- Admin Reauthorization ---
def admin_auth_page():
    st.subheader("🔑 Admin Reauthorization Required")
    if time.time() - st.session_state.lockout_time < LOCKOUT_SECONDS:
        st.error("Please wait before retrying.")
        return

    password = st.text_input("Admin Password", type="password")
    if st.button("Reauthorize"):
        if password == ADMIN_PASSWORD:
            st.success("Access restored.")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
        else:
            st.error("Incorrect admin password.")


# --- Main Control Flow ---
def main():
    st.set_page_config(page_title="Secure Data Vault", layout="centered")
    st.sidebar.title("🔐 Secure Vault")

    if st.session_state.user:
        home_page()
    else:
        page = st.sidebar.radio("Navigate", ["Login", "Register"])
        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            admin_auth_page()
        elif page == "Login":
            login_page()
        elif page == "Register":
            register_page()


if __name__ == "__main__":
    main()
