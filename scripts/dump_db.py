# Script for dumping database to view its contents

import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash


DB_FILE = "infosec_lab.db"

if not os.path.exists(DB_FILE):
    print(f" Database file '{DB_FILE}' not found. Are you running inside Docker?")
    exit(1)

conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("\n Dumping database contents...\n")

tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()

def all_tables():
    for t in tables:
        table = t[0]
        print(f"--- {table.upper()} ---")
        rows = cur.execute(f"SELECT * FROM {table}").fetchall()
        if not rows:
            print("(empty)")
        else:
            for row in rows:
                print(dict(row))
        print()

def users_table(table):
    for t in tables:
        if t[0] == table:
            print('USERS____________')
            rows = cur.execute(f"SElect * from {t[0]}").fetchall()
            if rows: 
                for row in rows:
                    print(dict(row))
        continue


def seed_users():
#  conn.execute()   INSERT INTO users (name, andrew_id, password, role) VALUES
# ('Alice Admin', 'alice', generate_password_hash('adminpass'), 'data_admin'), -- password: adminpass
# ('Bob Basic', 'bob', generate_password_hash('basicpass'), 'basic'), -- password: basicpass
# ('Charlie UserAdmin', 'charlie', generate_password_hash('useradminpass'), 'user_admin'); -- password: useradminpass

    conn.execute(f"INSERT INTO users (name, andrew_id, password, role) VALUES ('Alice Admin', 'alice', '{generate_password_hash('data')}', 'data_admin')")
    conn.execute(f"INSERT INTO users (name, andrew_id, password, role) VALUES ('Bob Basic', 'bob', '{generate_password_hash('basic')}', 'basic')")
    conn.execute(f"INSERT INTO users (name, andrew_id, password, role) VALUES ('Charlie UserAdmin', 'charlie', '{generate_password_hash('user')}', 'user_admin')")
    
    # seed the otps
    for andrew_id in ['alice', 'bob', 'charlie']:
        
        user_id = conn.execute("SELECT id FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()['id']
        import datetime, hashlib

        now = datetime.datetime.utcnow()
        base_time = now.replace(second=0, microsecond=0)

        # generatte OTP chaain for 24 hours
        for i in range(1440):
            otp_time = base_time + datetime.timedelta(minutes=i)
            timespamp = int(otp_time.strftime("%Y%m%d%H%M"))

            # generate OTP USING THE HASH
            seed = f"user_{user_id}_otp_seed_{timespamp}".encode()
            hash_result = hashlib.sha256(seed).hexdigest()
            otp_code = int (hash_result[:6], 16) % 1000000  # 6-digit OTP
            otp_code = f"{otp_code:06d}"

            # store the OTP IN DB
            conn.execute(
                "INSERT INTO otp_chain (user_id, timestamp, otp) VALUES (?, ?, ?)",
                (user_id, timespamp, otp_code)
            )
    
        
    
    conn.commit()
    print('seeded users')       



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Plese sepecify whether you want all tables or users only')
        sys.exit(1)

    func_to_run = sys.argv[1]

    if func_to_run[0] == 't':
        print(func_to_run[1:])
        users_table(func_to_run[1:])

    elif func_to_run == 'all':
        all_tables()

    elif func_to_run == 'seed':
        seed_users()
        
    else:
        print('unknown funciton')

conn.close()