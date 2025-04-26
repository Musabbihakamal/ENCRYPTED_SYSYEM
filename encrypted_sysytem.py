import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Simple way to keep data
stored_data = {}

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt text
def encrypt_text(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt text
def decrypt_text(text):
    return cipher.decrypt(text.encode()).decode()

# For keeping login state and failed attempts
if "authorized" not in st.session_state:
    st.session_state.authorized = True

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

st.title("🔐 SIMPLE DATA STORAGE APP")

if not st.session_state.authorized:
    st.subheader("🔑 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "1234":
            st.success("Login Successful!")
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
        else:
            st.error("Wrong Username or Password.")

else:
    menu = st.selectbox("Choose an option", ["Home", "Insert Data", "Retrieve Data"])

    if menu == "Home":
        st.write("👋 Welcome to the simple data storage app made by a beginner!")
        st.write("You can save and retrieve your text securely using a passkey.")

    elif menu == "Insert Data":
        st.subheader("📥 Insert Your Data")
        text = st.text_area("Enter some text")
        passkey = st.text_input("Enter a passkey", type="password")

        if st.button("Store Data"):
            if text and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_text(text)
                stored_data[hashed] = encrypted
                st.success("Data Stored Successfully!")
            else:
                st.error("Please fill both fields!")

    elif menu == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter your passkey to retrieve data", type="password")

        if st.button("Get Data"):
            if passkey:
                hashed = hash_passkey(passkey)
                if hashed in stored_data:
                    decrypted = decrypt_text(stored_data[hashed])
                    st.success("Here is your stored text:")
                    st.write(decrypted)
                    st.session_state.failed_attempts = 0
                else:
                    st.error("Wrong passkey!")
                    st.session_state.failed_attempts += 1
                    st.warning(f"Attempts: {st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.error("Too many failed attempts. Please login again.")
                        st.session_state.authorized = False
            else:
                st.error("Please enter a passkey.")
