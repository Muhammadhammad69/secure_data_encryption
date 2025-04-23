import streamlit as st
import os 
from hashlib import pbkdf2_hmac
import json
from cryptography.fernet import Fernet
import time






ITERAION = 1000000
USER_FILE_PATH = "users.json"

if st.session_state.get("user") is None:
    st.session_state["user"] = False

def load_users():
    if os.path.exists(USER_FILE_PATH) and os.path.getsize(USER_FILE_PATH) > 0:
        with open(USER_FILE_PATH, "r") as file:
            user_data = json.load(file)
            return user_data
    else:
        return []

def save_users(user):
    users = load_users()
    with open(USER_FILE_PATH, "w") as file:
        users.append(user)
        json.dump(users, file, indent=4)
        

def hash_password(password):
    SALT = os.urandom(16)
    hash_password = pbkdf2_hmac('sha256', password.encode(), SALT, ITERAION, dklen=32).hex()
    
    return {"salt": SALT.hex(), "password": hash_password}

def verify_password(password, salt):
    SALT = bytes.fromhex(salt)
    return pbkdf2_hmac('sha256', password.encode(), SALT, ITERAION, dklen=32).hex()
def login():
    st.subheader("🔑 Login")
    placeholder = st.empty()
    with placeholder.container():
        email = st.text_input("Enter your email", key="email-login")
        password = st.text_input("Password", type="password", key="password-login")
        login_btn = st.button("Login", key="login-btn")
    if login_btn:
        users = load_users()
        if len(users) == 0:
            st.error("No users registered", icon="🚫")
            return    
        for user in users:
            if user["email"] == email and user["password"] == verify_password(password, user["salt"]):
                st.session_state["user"] = True
                st.session_state["email"] = email
                
                placeholder.empty()
                st.success("Login successful and redirecting to home", icon="✅")
                time.sleep(2)
                st.rerun()
                return
                
        st.error("Invalid email or password", icon="❌")

def register():
    st.subheader("📝 Register")
    placeholder = st.empty()
    with placeholder.container():
        email = st.text_input("Enter your email", key="email-register")
        password = st.text_input("Password", type="password", key="password-register")
        register_btn = st.button("Register", key="register-btn")
        
    if register_btn:
        users = load_users()
        if  email in [user["email"] for user in users]:
            st.error("Email already exists", icon="❌")
            return
        pass_and_salt = hash_password(password)
        user = {
            "email": email, 
            "password": pass_and_salt["password"], 
            "salt": pass_and_salt["salt"],
            
            }
        save_users(user)
        st.session_state["user"] = True
        st.session_state["email"] = email
        st.session_state["key"] = user["key"]
        placeholder.empty()
        st.success("User registered successfully and redirecting to home", icon="✅")
        time.sleep(2)
        st.rerun()
        return
        
def change_password():
    st.subheader("🔑🔄 Change Password")
    placeholder = st.empty()
    with placeholder.container():
        email = st.session_state.email
        old_password = st.text_input("Enter your old password", type="password", key="old-password")
        new_password = st.text_input("Enter your new password", type="password", key="new-password")
        change_password_btn = st.button("Change Password", key="change-password-btn")
    if change_password_btn:
        if not old_password or not new_password:
            st.error("Please enter both old and new password", icon="❌")
            return
        users = load_users()
        for user in users:
            if user["email"] == email:
                # getting store salt (for verify the password)
                SALT = user["salt"]
                # create hashed password using verify password function
                getting_pass_hash = verify_password(old_password, SALT)
                if user["password"] == getting_pass_hash:
                    # create new password hashed using hashed password function 
                    hash_new_pass = hash_password(new_password)
                    # update the password in the user dictionary
                    user["password"] = hash_new_pass["password"]
                    # update the salt in the user dictionary
                    user["salt"] = hash_new_pass["salt"]
                    # update the user dictionary in the users file
                    with open(USER_FILE_PATH, "w") as file:
                        json.dump(users, file, indent=4)
                    
                    placeholder.empty()
                    st.success("Password changed successfully", icon="✅")
                    return
                else:
                    st.error("Invalid old password", icon="❌")
                    return    
            else:
                st.error("User not found", icon="❌")
                return        
            



