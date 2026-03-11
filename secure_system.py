import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session states
if "failed_attempt" not in st.session_state:
    st.session_state.failed_attempt = 0
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "current_page" not in st.session_state:
    st.session_state.current_page = "HOME"
if "last_attempt_time" not in st.session_state:
    st.session_state.last_attempt_time = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate Fernet key from passkey
def generate_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt text
def encrypt_data(text, passkey):
    key = generate_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_data(encrypted_text, passkey):
    try:
        key = generate_from_passkey(passkey)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempt = 0
        return decrypted
    except:
        st.session_state.failed_attempt += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Generate unique data ID
def generate_data_id():
    return str(uuid.uuid4())

# Reset failed login attempts
def reset_failed_attempt():
    st.session_state.failed_attempt = 0

# Navigate to another page
def change_page(page):
    st.session_state.current_page = page

# Title
st.title("🔐 SECURE DATA ENCRYPTION SYSTEM")

# Sidebar menu
menu = ["HOME", "STORE DATA", "RETRIEVED DATA", "LOGIN"]
choice = st.sidebar.selectbox("🔎 NAVIGATION", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Auto-redirect to login on 3 failed attempts
if st.session_state.failed_attempt >= 3:
    st.session_state.current_page = "LOGIN"
    st.warning("🚫 Too many failed attempts! Please reauthorize.")

# HOME
if st.session_state.current_page == "HOME":
    st.subheader("🏠 Welcome to Secure Data System")
    st.write("Use this app to **securely store and retrieve** your text using a passkey.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 STORE NEW DATA", use_container_width=True):
            change_page("STORE DATA")
    with col2:
        if st.button("🔐 RETRIEVE DATA", use_container_width=True):
            change_page("RETRIEVED DATA")

    st.info(f"🔒 Currently storing {len(st.session_state.stored_data)} encrypted entries.")

# STORE DATA
elif st.session_state.current_page == "STORE DATA":
    st.subheader("📥 Store Your Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("🔒 Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("❗ Passkeys do not match.")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data stored securely!")
                st.code(data_id, language="text")
                st.info("📌 Save this Data ID to retrieve your data.")
        else:
            st.error("❗ All fields are required.")

# RETRIEVE DATA
elif st.session_state.current_page == "RETRIEVED DATA":
    st.subheader("🔍 Retrieve Your Data")
    attempts_remaining = 3 - st.session_state.failed_attempt
    st.info(f"🕵️ Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                hashed_pass = st.session_state.stored_data[data_id]["passkey"]

                if hash_passkey(passkey) == hashed_pass:
                    decrypted_text = decrypt_data(encrypted_text, passkey)
                    if decrypted_text:
                        st.success("✅ Decryption Successful!")
                        st.markdown("### 🔐 Your Secret Data:")
                        st.code(decrypted_text, language="text")
                    else:
                        st.error("❗ Decryption failed!")
                else:
                    st.error(f"❗ Incorrect passkey! Remaining: {3 - st.session_state.failed_attempt}")
            else:
                st.error("❗ Data ID not found.")
        else:
            st.warning("❗ Both fields are required.")

# LOGIN
elif st.session_state.current_page == "LOGIN":
    st.subheader("🔐 Reauthorization Required")

    if time.time() - st.session_state.last_attempt_time < 10:
        wait_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Please wait {wait_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if login_pass == "admin123":
                reset_failed_attempt()
                st.success("✅ Reauthorized successfully!")
                st.session_state.current_page = "HOME"
                st.rerun()
            else:
                st.error("❗ Incorrect master password!")

# Footer
st.markdown("---")
st.caption("🔐 Secure Data Encryption System | Made by a beginner 👨‍💻")
