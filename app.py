from pathlib import Path
import os
from io import BytesIO
import streamlit as st
from dotenv import load_dotenv

# Authentication Imports
import sqlite3
from sqlite3 import Error
import bcrypt

# LangChain/RAG Imports
from langchain_groq import ChatGroq
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import FAISS
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_classic.chains.retrieval import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
from langchain_huggingface import HuggingFaceEmbeddings

os.environ["TOKENIZERS_PARALLELISM"] = "false"

# --- RAG/GROQ Configuration ---
load_dotenv()
groq_key = os.getenv("GROQ_API_KEY")

DATABASE_FILE = "project.db"

def create_connection(db_file):
    """Creates and returns a connection object to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        # Note: In production, log this error instead of just printing
        print(f"Database Connection Error: {e}")
        return None

def setup_database(conn):
    """Creates the necessary users table if it doesn't exist."""
    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(create_users_table)
        conn.commit()
    except Error as e:
        print(f"Database Setup Error: {e}")

def add_user(conn, username, password_hash):
    """Inserts a new user. Returns True on success, False on failure (username exists)."""
    insert_query = "INSERT INTO users (username, password_hash) VALUES (?, ?);"
    try:
        cursor = conn.cursor()
        cursor.execute(insert_query, (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Error as e:
        print(f"ERROR inserting user: {e}")
        return False

def get_user_hash(conn, username):
    """Fetches the password hash for a given username."""
    select_query = "SELECT password_hash FROM users WHERE username = ?;"
    try:
        cursor = conn.cursor()
        cursor.execute(select_query, (username,))
        result = cursor.fetchone()
        return result[0] if result else None
    except Error as e:
        print(f"ERROR fetching user hash: {e}")
        return None


def hash_password(password):
    """Hashes a plaintext password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(plain_password, hashed_password_from_db):
    """Verifies a plaintext password against a stored hash."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password_from_db.encode('utf-8'))
    except ValueError:
        return False

# --- RAG Core Functions ---

if "vector_store" not in st.session_state:
    st.session_state.vector_store = None

@st.cache_resource
def get_vector_store(uploaded_file):
    """Processes the PDF, creates chunks, and generates FAISS vector store."""
    bytes_data = uploaded_file.getvalue()
    file_stream = BytesIO(bytes_data)

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(file_stream.read())
        temp_filepath = tmp_file.name
    try:
        loader = PyPDFLoader(temp_filepath)
        documents = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        chunks = text_splitter.split_documents(documents)

        # Using a reliable HuggingFace Embedding model
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        vector_store = FAISS.from_documents(chunks, embeddings)
        st.success("Document processing complete! You can now chat.")
        return vector_store
    except Exception as e:
        st.error(f"Error processing PDF: {e}")
        return None
    finally:
        os.remove(temp_filepath)

# --- Authentication Interface ---

def authentication_interface(conn):
    """Handles the Login/Signup forms and state management."""

    # Initialize session state for tracking authentication and mode
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = None
    if 'auth_mode' not in st.session_state:
        st.session_state.auth_mode = 'login'

    st.title("User Authentication Required")

    # Container ensures the forms replace each other cleanly
    auth_container = st.container(border=True)

    if st.session_state.auth_mode == 'login':
        # --- LOGIN FORM ---
        with auth_container:
            st.subheader("Login to Access RAG Model")
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type='password', key="login_pass")

            col1, col2 = st.columns([1, 2])

            with col1:
                if st.button("Login", use_container_width=True):
                    if not username or not password:
                        st.error("Please enter both username and password.")
                        st.stop()

                    stored_hashed_password = get_user_hash(conn, username)

                    if stored_hashed_password is not None and verify_password(password, stored_hashed_password):
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.rerun()  # Forces a refresh to show the RAG content
                    else:
                        st.error("Invalid Username or Password.")

            with col2:
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
                        st.stop()

                    hashed_new_password = hash_password(new_password)

                    if add_user(conn, new_username, hashed_new_password):
                        st.success("Account created successfully! Please log in.")
                        st.session_state.auth_mode = 'login'
                        st.rerun()
                    else:
                        st.error("Signup failed. That username might already be taken.")

            with col2:
                if st.button("Already have an account? Log In", key="switch_to_login", use_container_width=True):
                    st.session_state.auth_mode = 'login'
                    st.rerun()


# --- Main Application Logic (RAG) ---

def rag_application():
    """The core RAG application logic, only runs if authenticated."""
    st.title(f"Interactive RAG Model")
    st.title(f"Welcome,  {st.session_state.username}")
    # ----------------------------------------------------
    # 1. RAG Sidebar and Document Processing
    # ----------------------------------------------------
    with st.sidebar:
        st.header("Document Upload")
        st.write(f"Logged in as: **{st.session_state.username}**")
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.vector_store = None  # Clear knowledge base on logout
            st.session_state["messages"] = []  # Clear chat history
            st.rerun()

        st.header("Upload File Below")
        uploaded_file = st.file_uploader(
            "Upload a File to Analyze",
            type="pdf",
            accept_multiple_files=False
        )
        process_button = st.button("Create Knowledge Base")

        if uploaded_file and process_button:
            with st.spinner("Processing document and generating embeddings..."):
                # Clear existing store to load new document
                st.session_state.vector_store = get_vector_store(uploaded_file)

    # ----------------------------------------------------
    # 2. RAG Chat Interface
    # ----------------------------------------------------
    if st.session_state.vector_store:
        # LLM and Chain Setup (happens once after vector store is ready)
        llm = ChatGroq(groq_api_key=groq_key, model="llama-3.3-70b-versatile")
        prompt = ChatPromptTemplate.from_template("""
        You are an expert Assistant and your task is to answer the user's question.
        **Crucially, use ONLY the information in the provided context to formulate your answer.**
        If the answer is not in the context, you MUST state, "The answer is not available in the provided document."
        CONTEXT: {context}
        QUESTION: {input}
        """)
        document_chain = create_stuff_documents_chain(llm, prompt)
        retriever = st.session_state.vector_store.as_retriever()
        retrieval_chain = create_retrieval_chain(retriever, document_chain)

        if "messages" not in st.session_state:
            st.session_state["messages"] = [
                {"role": "assistant", "content": "Hello! I'm ready to answer questions about your uploaded document."}]

        # Display chat history
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # Handle user input
        if user_query := st.chat_input("Ask a question about the document..."):
            st.session_state.messages.append({"role": "user", "content": user_query})
            with st.chat_message("user"):
                st.markdown(user_query)

            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    response = retrieval_chain.invoke({"input": user_query})
                    st.markdown(response["answer"])


                    sources = "\n".join([doc.metadata.get("source", "No source info") for doc in response["context"]])
                    with st.expander("Sources"):
                        st.text(sources)

            st.session_state.messages.append({"role": "assistant", "content": response["answer"]})

    else:
        st.info("Please upload a PDF document and click 'Create Knowledge Base' to begin.")


# ----------------------------------------------------------------------
# FINAL APPLICATION ENTRY POINT
# ----------------------------------------------------------------------
def main():
    if not groq_key:
        st.error("GROQ_API_KEY not found. Please set it in your environment or Streamlit secrets.")
        st.stop()

    conn = create_connection(DATABASE_FILE)
    if conn is None:
        st.stop()

    setup_database(conn)

    if st.session_state.get('authenticated', False):
        rag_application()
    else:
        authentication_interface(conn)

    if conn:
        conn.close()

if __name__ == '__main__':
    main()
