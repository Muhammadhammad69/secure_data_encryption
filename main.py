import auth
import data_manager
import streamlit as st



if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_start_time' not in st.session_state:
    st.session_state.lockout_start_time = None
if "lockout_attempts" not in st.session_state:
    st.session_state.lockout_attempts = 0
if "lockout_duration" not in st.session_state:
    st.session_state.lockout_duration = 0


def home_page_ui():
    # welcome
    st.subheader("🏠 Welcome to the Secure Data System")
    
    # Short Description
    st.write("A safe place for your sensitive data. Encrypt, store, and retrieve it anytime with complete security.")

    # Section Divider
    st.markdown("---")

    # Key Features
    st.markdown("### ✨ Key Features:")
    st.markdown("""
    - 🔒 End-to-End Encryption
    - 🔑 Unique Passkey-Based Access
    - ⚡ Fast, Lightweight, and User-Friendly
    """)
    
    # Security Disclaimer
    st.markdown("---")
    st.info("**Note:** If you lose your passkey, your data cannot be recovered. Please keep it safe.")

    # Motivational Line
    st.success("Your secrets deserve the highest protection — because security is a promise, not just a feature.")

    # Footer
    st.markdown("---")
    st.caption("Version 1.0 | Last Updated: April 2025")

st.title("🔐 Secure Data Encryption System")

# st.write(st.session_state)
# check if user is logged in
if not st.session_state.get("user"):
    # menu 
    menu= ["Login", "Register"]
    # select menu
    choice = st.sidebar.selectbox("Menu", menu, index=0)

    
    if choice == "Login":
        auth.login()
        # st.write("Login")
    elif choice == "Register":
        auth.register()
        # st.write("Register")

elif st.session_state.get("user"):
    menu = ["Home", "Manage Data", "Change Password", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu, index=0)
    if choice == "Home":
        home_page_ui()
    elif choice == "Manage Data":
        manage_data = st.sidebar.radio("Select one",["Store Data", "Retrieve Data"], label_visibility="hidden")
        if manage_data == "Store Data":
            data_manager.store_data()
        elif manage_data == "Retrieve Data":
            data_manager.retrieve_data()
    elif choice == "Change Password":
        auth.change_password()    
    elif choice == "Logout":
        st.session_state.pop("user")
        st.session_state.pop("email")
        st.session_state.pop("key")
        st.rerun()