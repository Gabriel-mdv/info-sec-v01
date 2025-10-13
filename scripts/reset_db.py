# This script is used for resetting the users table contents

import sqlite3
import os

DB_FILE = "infosec_lab.db"

def reset_db():
    if not os.path.exists(DB_FILE):
        print("[!] Database file does not exist.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Delete all records from the users table
    cursor.execute("DELETE FROM users;")
    cursor.execute("DELETE FROM files")
    cursor.execute("DELETE FROM otp_chain")
    cursor.execute('DELETE FROM audit_logs')
    conn.commit()
    conn.close()

    print("[*] Users table has been cleared. Database reset done.")

if __name__ == "__main__":
    reset_db()