import sqlite3
import os

# Reset the vault by deleting the master password
vault_db = "vault.db"

if os.path.exists(vault_db):
    try:
        conn = sqlite3.connect(vault_db)
        conn.execute("DELETE FROM master")
        conn.commit()
        conn.close()
        print("✅ Master password reset successfully!")
        print("🔓 You can now run vault.py and create a new master password.")
    except Exception as e:
        print(f"❌ Error: {e}")
else:
    print("❌ vault.db not found. Run vault.py first to create it.")
