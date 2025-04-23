import os 
from hashlib import pbkdf2_hmac
import json
from cryptography.fernet import Fernet
import streamlit as st
import time
from datetime import datetime
# generate salt for passkey
SALT = os.urandom(16)
ITERAION = 1000000

#file path
FILE_PATH = "data.json"

# lockout variables
MAX_ATTEMPTS = 3
lockout_duration = 15

# initialize session state

# function to load data in file
def load_data():
    if os.path.exists(FILE_PATH) and os.path.getsize(FILE_PATH) > 0:
        with open(FILE_PATH, "r") as file:

            data = json.load(file)
            return data
    return []

# function to save data in file
def save_data(data):
    file_data = load_data()
    with open(FILE_PATH, "w") as file:
        file_data.append(data)
        json.dump(file_data, file, indent=4)
        
        
#function to hashed Passkey
def hash_passkey(passkey):
    return pbkdf2_hmac('sha256', passkey.encode(), SALT, ITERAION, dklen=32).hex()
# function to verify passkey
def verify_passkey(passkey, salt, stored_passkey):
    # salt convert to bytes
    SALT = bytes.fromhex(salt)
    # create passkey
    hash_passkey = pbkdf2_hmac('sha256', passkey.encode(), SALT, ITERAION, dklen=32).hex()
    # check if passkey is correct
    if hash_passkey == stored_passkey:
        return True
    return False

# function to generate key
def generate_key():
    KEY = Fernet.generate_key()
    return KEY.hex()

def is_locked_out():
    
    lockout_duration = st.session_state.lockout_duration
    if st.session_state.lockout_start_time is None:
        return False
    elapsed = time.time() - st.session_state.lockout_start_time
    if elapsed >= lockout_duration:
        # Reset lockout after time passed
        
        st.session_state.lockout_start_time = None
        lockout_duration += 15
        return False
    return True

# check if user is logged in
def check_user():
    if st.session_state["user"] == False:
        st.rerun()
        return

    # function to encrypt data
def encrypt_data(data):
    KEY = generate_key()
    cipher = Fernet(bytes.fromhex(KEY))
    encrypted_data = cipher.encrypt(data.encode()).decode()
    return {"encrypted_data": encrypted_data, "text_passkey": KEY}
    
    # function to decrypt data using passkey
def decrypt_data(label, passkey="none"):
    # load data in file 
    file_data = load_data()
    # check if file is empty
    if len(file_data) == 0:
        return "none"
    
    #loop through file data
    for data in file_data:
        if data["label"] == label:
            # initialize variables 
            store_passkey = data["passkey"]
            store_salt = data["salt"]
            
            # check if passkey is correct if correct return True else False
            check_passkey = verify_passkey(passkey, store_salt, store_passkey)
            if not check_passkey:
                return "none"
            
            # get the key from file
            KEY = data["text_passkey"]
            cipher = Fernet(bytes.fromhex(KEY))
            # decrypt the data
            decrypted_data = cipher.decrypt(data["encrypted_data"].encode()).decode()
            return_data = {
                "label": data["label"],
                "decrypted_data": decrypted_data,
                "created_date": data["created_date"]
            }
            return return_data
        else:
            return "none"
    # loop through file data
    # for data in file_data:
    #     # initialize variables
            
    #     is_data_decrypted = False
    #     store_salt = "none"
    #     store_passkey = "none"
    #     if data["encrypted_data"] == text:
    #         # get the key from file
    #         KEY = data["text_passkey"]
    #         cipher = Fernet(bytes.fromhex(KEY))
    #         # decrypt the data
    #         # st.write("Decrypting data...")
    #         decrypted_data = cipher.decrypt(data["encrypted_data"].encode()).decode()
    #         is_data_decrypted = True
    #         # get the salt and passkey in file data
    #         store_salt  = data["salt"]
    #         store_passkey = data["passkey"]
    #         break
    # # check if decrypted data is none so that we can return
    # if not is_data_decrypted:
    #     return "none"    
    # # check if user decrypted the data without a passkey    
    # if store_passkey == "none":
    #     # return the decrypted data
    #     return decrypted_data
    # else:
        # check if user decrypted the data with a passkey
        # if store_passkey != "none" and store_salt != "none":
        #     # verify the passkey
        #     hashed_passkey = verify_passkey(passkey, store_salt)
        #     # check if the passkey is valid and the decrypted data is correct
        #     if hashed_passkey == store_passkey:
        #         # return the decrypted data
        #         return decrypted_data
        #     else:
        #         return "none"
        # else:
        #     return "none"
   
   
is_label = False 
def store_data():
    check_user()
    user_email = st.session_state.email
    
    st.subheader("🛡️ Encrypt your data")
    def handle_label_change():
        global is_label
        load_users_data = load_data()
        # st.write(is_label)
        if len(load_users_data) == 0:
            is_label = False
            return
        label = st.session_state.store_label
        for data in load_users_data:
            if data["email"] == user_email:
                
                if data["label"].lower() == label.strip().lower():
                    
                    is_label = True
                    return
        is_label = False          
             
    # getting user input
    placeholder = st.empty()
    with placeholder.container():
        label = st.text_input("Enter unique label", key="store_label" , on_change=handle_label_change)
        
        if is_label:
            st.write("Label already exists use another label")
  
        text = st.text_area("Enter data to encrypt", key="encrypted_text")   
        # getting user input
        custom_passkey = st.text_input("Enter a custom passkey", key="store_passkey", type="password") 
        encrypt_btn = st.button("Encrypt and Save")
    if encrypt_btn:
        # check if label is already exists or not 
        user_data = load_data()
        if len(user_data) > 0:
            # filter the user data and check if label already exists
            is_label_exists = [True for data in user_data if data["email"] == user_email if data["label"].lower() == label.strip().lower()]

            if str(is_label_exists) == "[True]":
                st.toast("Label already exists use another label", icon="❌")
                return
        
        # change_input_values()
        # check if user wants to encrypt with a custom passkey
        if custom_passkey and text:
            # encrypt the data using the custom passkey
            data = encrypt_data(text)
            # hash the custom passkey
            gen_hashed_passkey = hash_passkey(custom_passkey)
            # save the encrypted data
            save_data({
                "label": label.strip(),
                "email": user_email.strip(),
                "encrypted_data": data["encrypted_data"], 
                "text_passkey": data["text_passkey"],
                "passkey": gen_hashed_passkey, 
                "salt": SALT.hex(),
                "created_date": datetime.now().strftime("%d %B %Y")
                })
            st.toast("Data encrypted and saved successfully", icon="✅")
        else:
            st.toast("❌ Please enter text and passkey")
            return
        placeholder.empty()
        st.success("Data encrypted and saved successfully", icon="✅")
        st.write("### Encrypt another data")
        if st.button("Encrypt another data", key="encrypt_another"):
            st.rerun()
    
def retrieve_data():
    global lockout_duration
    st.subheader("🔑 Decrypt your data")
     
    if is_locked_out():
        lockout_duration = st.session_state.lockout_duration
        remaining = int(lockout_duration - (time.time() - st.session_state.lockout_start_time))
        placeholder = st.empty()
        placeholder.error(f"🚫⏳ Locked out! Try again in {remaining} seconds.")
        time.sleep(1)
        st.rerun()
        st.stop()
             
    elif not is_locked_out():
        #user email
        user_email = st.session_state.email
        # load user file data and getting all the label of the user
        user_data = load_data()
        if len(user_data) > 0:
            all_label = [data["label"] for data in user_data if data["email"] == user_email]            
        else:
            all_label = []
        all_label = ["Select Label"] + all_label
        placeholder = st.empty()
        with placeholder.container(): 
            # getting user input
            label = st.selectbox("Select a label", all_label, key="retrieve_label")   
           
            
            # getting user input
            custom_passkey = st.text_input("Enter a custom passkey", key="custom_passkey", type="password")
            decrypt_btn = st.button("Decrypt")
        if decrypt_btn:
                   
            if custom_passkey and label:
                # decrypt the data using the custom passkey
                data = decrypt_data(label, custom_passkey)
                # check if the decrypted data is none
                    
                if data == "none":
                    st.session_state.failed_attempts += 1
                    st.toast("Invalid data" , icon="❌")  
                else:
                    st.session_state.failed_attempts = 0
                    lockout_duration = 15
                    st.toast("Data decrypted successfully" , icon="✅")
                    placeholder.empty()
                    st.success("Data decrypted successfully", icon="✅")
                    
                    container =st.container()
                    with container:
                        st.markdown(
                        f"**✅ Decrypted Text:**<br>{data['decrypted_data']}",
                        unsafe_allow_html=True
                        )
                        # st.markdown(f"##### {data['decrypted_data']}")
                        st.markdown(f"**📌 Title:**<br>{data['label']}",
                        unsafe_allow_html=True
                        )
                        st.markdown(f"**📅 Created On:**<br>{data['created_date']}",
                        unsafe_allow_html=True
                        )
                    if st.button("Decrypt another data", key="decrypt_another"):
                        st.rerun()
                    output_data = f"✅ Decrypted Text:\
                        \n{data['decrypted_data']}\
                        \n\
                        \n📌 Title:\
                        \n{data['label']}\
                        \n\
                        \n📅 Created On:\
                        \n{data['created_date']}"
                    st.download_button("Download Decrypted Data", file_name="decrypted_data.txt", data=output_data)
                        
                    # st.text_area("Decrypted Output", value=data)
            else:
                # st.session_state.failed_attempts += 1
                st.toast("Please enter label and passkey", icon="❌")
                # if st.session_state.failed_attempts == MAX_ATTEMPTS:
                
            
            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                placeholder.empty()
                st.session_state.user = False
                st.error("⛔ Too many failed attempts Locked out! Please register or login again.")
                time.sleep(2)
                st.session_state.failed_attempts = 0
                lockout_duration = 15
                st.rerun()
                return
                   
                
                  
            if st.session_state.failed_attempts < MAX_ATTEMPTS:
                failed_attempt = st.session_state.failed_attempts
                if st.session_state.lockout_start_time:
                    pass
                elif failed_attempt > 0:
                    st.session_state.lockout_duration = 15 * failed_attempt
                    st.session_state.lockout_start_time =time.time()
                    st.rerun()
                    # st.error(f"⛔Try again in {lockout_duration} seconds.")
                    # st.toast(f"Failed attempts: {failed_attempt}")