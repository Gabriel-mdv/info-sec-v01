
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "../infosec_lab.db")

def drop_db():
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
            print(f'successfully removed {DB_FILE}')

        except OSError as e:
            print(f'[!] Error: could not delete {DB_FILE}')


if __name__ == '__main__':
    drop_db()




