import sqlite3

# Connect to SQLite DB (creates file if not exists)
conn = sqlite3.connect('signatures.db')

# Create a cursor object to execute SQL
cursor = conn.cursor()

# Create table for malware signatures
cursor.execute('''
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256_hash TEXT UNIQUE NOT NULL,
    malware_name TEXT,
    malware_type TEXT,
    threat_level TEXT,
    added_on TEXT DEFAULT CURRENT_TIMESTAMP
)
''')

# Save changes and close
conn.commit()
conn.close()
