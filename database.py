import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Initialize Database
# =========================
def init_db():
    conn = sqlite3.connect('attacks.db')
    c = conn.cursor()

    # 🔹 Attacks table
    c.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            username TEXT,
            headers TEXT,
            prediction TEXT,
            timestamp TEXT,
            country TEXT
        )
    ''')

    # 🔹 Admin users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    conn.commit()
    conn.close()


# =========================
# Insert attack log
# =========================
def insert_attack(ip, username, headers, prediction, timestamp, country):
    try:
        conn = sqlite3.connect('attacks.db')
        c = conn.cursor()

        # Truncate oversized payloads to prevent DB bloat from attacks
        headers = str(headers)[:5000] if headers else ""
        username = str(username)[:500] if username else ""

        c.execute(
            "INSERT INTO attacks (ip, username, headers, prediction, timestamp, country) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, username, headers, prediction, timestamp, country)
        )

        conn.commit()
        conn.close()
    except Exception:
        pass


# =========================
# Fetch all attacks
# =========================
def fetch_all_attacks():
    conn = sqlite3.connect('attacks.db')
    c = conn.cursor()

    c.execute("SELECT * FROM attacks ORDER BY id DESC")
    rows = c.fetchall()

    conn.close()
    return rows


# =========================
# Admin functions (Password Hashing)
# =========================
def create_admin(username, password):
    conn = sqlite3.connect('attacks.db')
    c = conn.cursor()

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    c.execute(
        "INSERT INTO admins (username, password) VALUES (?, ?)",
        (username, hashed_pw)
    )

    conn.commit()
    conn.close()


def check_admin(username, password):
    conn = sqlite3.connect('attacks.db')
    c = conn.cursor()

    c.execute(
        "SELECT * FROM admins WHERE username=?",
        (username,)
    )

    admin = c.fetchone()
    conn.close()

    if admin and check_password_hash(admin[2], password):
        return admin
    return None