import sqlite3
from sqlite3 import Error

# --- Configuration (Must match in both files) ---
DATABASE_FILE = "project.db"
def create_connection(db_file):
    """Creates and returns a connection object to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(f"Database Connection Error: {e}")
        return None

def setup_database(conn):
    """Creates the necessary users table if it doesn't exist.
    This structure is specifically for user authentication.
    """
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
    """
    Inserts a new user and their hashed password into the database.
    Returns True on success, False on failure (e.g., username already exists).
    """
    insert_query = """
    INSERT INTO users (username, password_hash)
    VALUES (?, ?);
    """
    try:
        cursor = conn.cursor()
        # Using a tuple (username, password_hash) prevents SQL injection
        cursor.execute(insert_query, (username, password_hash))
        conn.commit()
        print(f"User '{username}' successfully added to the database.")
        return True
    except sqlite3.IntegrityError:
        # This occurs because 'username' is set to UNIQUE NOT NULL
        print(f"ERROR: Username '{username}' already exists.")
        return False
    except Error as e:
        print(f"ERROR inserting user: {e}")
        return False

def get_user_hash(conn, username):
    """
    Fetches the password hash for a given username.
    Returns the hash string if found, otherwise None.
    """
    select_query = "SELECT password_hash FROM users WHERE username = ?;"
    try:
        cursor = conn.cursor()
        cursor.execute(select_query, (username,))
        # fetchone() returns a tuple, so we grab the first element [0]
        result = cursor.fetchone()
        return result[0] if result else None
    except Error as e:
        print(f"ERROR fetching user hash: {e}")
        return None
