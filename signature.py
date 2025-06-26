import sqlite3

def init_db():
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256_hash TEXT UNIQUE NOT NULL,
            malware_name TEXT,
            threat_level TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()
