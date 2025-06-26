import hashlib, sqlite3

eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
eicar_hash = hashlib.sha256(eicar_string.encode()).hexdigest()

conn = sqlite3.connect("signatures.db")
cursor = conn.cursor()
cursor.execute("INSERT OR IGNORE INTO signatures (sha256_hash, malware_name, threat_level) VALUES (?, ?, ?)",
            (eicar_hash, "EICAR-Test-File", "High"))
conn.commit()
conn.close()

print("✅ EICAR hash added.")
