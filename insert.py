import sqlite3
def import_hashes_from_txt(file_path):
    conn = sqlite3.connect('signatures.db')
    cursor = conn.cursor()

    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) >= 1:
                sha256 = parts[0]
                name = parts[1] if len(parts) > 1 else "Unknown"
                level = parts[2] if len(parts) > 2 else "Medium"
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO signatures (sha256_hash, malware_name, threat_level)
                        VALUES (?, ?, ?)
                    ''', (sha256, name, level))
                except Exception as e:
                    print("Error:", e)

    conn.commit()
    conn.close()

# Example
import_hashes_from_txt('hard_signatures/SHA256-Hashes_pack1.txt')
import_hashes_from_txt('hard_signatures/SHA256-Hashes_pack2.txt')
import_hashes_from_txt('hard_signatures/SHA256-Hashes_pack3.txt')
