import streamlit as st
import bcrypt

from database_logic import create_connection, add_user, get_user_hash, setup_database, DATABASE_FILE
def hash_password(password):
    """Hashes a plaintext password using bcrypt"""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(plain_password, hashed_password_from_db):
    """Verifies a plaintext password against a stored hash"""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'),hashed_password_from_db.encode('utf-8'))
    except ValueError:
        return False

#----  Main Screen ----#
def main():
    # 1. CONNECT TO THE DATABASE AND SETUP TABLES
    conn = create_connection(DATABASE_FILE)

    if conn is None:
        st.error("🚨 Database connection failed. Check your console for details.")
        return

    setup_database(conn)

    # Initialize session state for tracking authentication and mode
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = None

    # Initialize the mode: 'login' or 'signup'
    if 'auth_mode' not in st.session_state:
        st.session_state.auth_mode = 'login'

    st.title("Streamlit User Authentication")

    # --- LOGGED IN STATE ---
    if st.session_state.authenticated:
        st.success(f"Welcome back, {st.session_state.username}! Access granted.")
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.rerun()

    # --- LOGGED OUT STATE (Forms) ---
    else:
        # Container ensures the forms replace each other cleanly
        auth_container = st.container(border=True)

        if st.session_state.auth_mode == 'login':
            # --- LOGIN FORM ---
            with auth_container:
                st.subheader("Login to Your Account")
                username = st.text_input("Username", key="login_user")
                password = st.text_input("Password", type='password', key="login_pass")

                col1, col2 = st.columns([1, 2])

                with col1:
                    if st.button("Login", use_container_width=True):
                        # Use database logic to retrieve the hash
                        stored_hashed_password = get_user_hash(conn, username)

                        if stored_hashed_password is not None and verify_password(password, stored_hashed_password):
                            st.session_state.authenticated = True
                            st.session_state.username = username
                            st.success("Login successful!")
                            st.rerun()
                        else:
                            st.error("Invalid Username or Password.")

                with col2:
                    # Button to switch to the Signup mode
                    if st.button("Need an account? Sign Up", key="switch_to_signup", use_container_width=True):
                        st.session_state.auth_mode = 'signup'
                        st.rerun()


        elif st.session_state.auth_mode == 'signup':
            # --- SIGNUP FORM ---
            with auth_container:
                st.subheader("Create New Account")
                new_username = st.text_input("Username", key="signup_user")
                new_password = st.text_input("Password", type='password', key="signup_pass")

                col1, col2 = st.columns([1, 2])

                with col1:
                    if st.button("Signup", use_container_width=True):
                        if not new_username or not new_password:
                            st.warning("Please fill in all fields.")
                        else:
                            # Hash password and use database logic to store
                            hashed_new_password = hash_password(new_password)

                            if add_user(conn, new_username, hashed_new_password):
                                st.success("Account created successfully! Please log in.")
                                # Auto-switch back to login mode on successful signup
                                st.session_state.auth_mode = 'login'
                                st.rerun()
                            else:
                                st.error("Signup failed. Username might already be taken.")

                with col2:
                    # Button to switch back to the Login mode
                    if st.button("Already have an account? Log In", key="switch_to_login", use_container_width=True):
                        st.session_state.auth_mode = 'login'
                        st.rerun()

    # 4. CLOSE THE CONNECTION
    if conn:
        conn.close()

if __name__ == '__main__':
    main()