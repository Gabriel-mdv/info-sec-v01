"""
Information Security Fall 2025 Lab - Flask Application
-----------------------------------------------------
Short description: Minimal course-branded web app that supports registration
(Name, Andrew ID, Password), login, session-based greeting, and logout.
Includes a landing page and CMU-themed styling.

Routes:
- GET /          : Landing page with welcome message + Login/Register buttons.
- GET/POST /register : Register with name, Andrew ID, and password; on success redirect to /login.
- GET/POST /login    : Login with Andrew ID + password; on success redirect to /dashboard.
- GET /dashboard     : Greets authenticated user: "Hello {Name}, Welcome to Lab 0 of Information Security course. Enjoy!!!"
- GET /logout        : Clear session and return to landing page.
"""
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
from helpers.encrypt_file import encrypt_file
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "infosec_lab.db")

# ___________ for file uploader _________________- 

from werkzeug.utils import secure_filename
from datetime import datetime

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ---------------- Database Helpers ----------------
def get_db():
    """Open a connection to SQLite with Row access."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database by executing schema.sql (single source of truth)."""
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    conn = get_db()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)


# ---------------- Utility ----------------
def current_user():
    """Return the current logged-in user row or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user

# ---------------- Routes ----------------
@app.route("/")
def index():
    """Landing page with CMU-themed welcome and CTA buttons."""
    return render_template("index.html", title="Information Security Fall 2025 Lab", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not andrew_id or not password:
            flash("All fields are required.", "error")
            return render_template("register.html", title="Register")

        # Hash the password with salt
        hashed_password = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (name, andrew_id, password) VALUES (?, ?, ?)",
                (name, andrew_id, hashed_password)
            )
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            conn.close()
    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        andrew_id = request.form.get("andrew_id", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        query = "SELECT * FROM users WHERE andrew_id = ?"
        user = conn.execute(query, (andrew_id,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session['andrew_id'] = user['andrew_id']
            return redirect(url_for("dashboard"))
        flash("Invalid Andrew ID or password.", "error")
    return render_template("login.html", title="Login")



# @app.route("/dashboard")
# def dashboard():
#     """Authenticated page greeting the user per the requirements."""
#     user = current_user()
#     if not user:
#         return redirect(url_for("login"))
#     greeting = f"Hello {user['name']}, Welcome to Lab 0 of Information Security course. Enjoy!!!"
#     return render_template("dashboard.html", title="Dashboard", greeting=greeting, user=user)

# _______________ upload the file ___________________ 
@app.route("/upload", methods=["POST"])
def upload_file():
    user = current_user()
    print(type(user))
    
    if not user:
        return redirect(url_for("login"))

    file = request.files.get("file")
    if not file:
        flash("No file selected", "error")
        return redirect(url_for("dashboard"))
    
    # Secure the filename
    original_name = secure_filename(file.filename)
    if original_name == "":
        flash("Invalid file name.", "error")
        return redirect(url_for("dashboard"))

    # Save file to disk with unique name
    stored_name = f"{user['andrew_id']}_{int(datetime.utcnow().timestamp())}_{original_name}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    # file.save(path) this saved the data as plain text
    # Encrypt file data before saving
    file_data = file.read()
    encryped_data = encrypt_file(file_data)

    with open(path, 'wb') as f:
        f.write(encryped_data)

    # Insert data into DB
    conn = get_db()
    conn.execute(
        "INSERT INTO files (user_id, filename, stored_name, size) VALUES (?, ?, ?, ?)",
        (user["id"], user['andrew_id']+original_name, stored_name, os.path.getsize(path)),
    )
    conn.commit()
    conn.close()

    flash("File uploaded successfully!", "success")
    return redirect(url_for("dashboard"))




# _____________ list file by updating the dashboard route __________________- 
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    files = conn.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
        (user["id"],)
    ).fetchall()
    conn.close()

    greeting = f"Hello {user['name']}, Welcome to Lab 2 of Information Security course. Enjoy!!!"
    return render_template("dashboard.html", title="Dashboard", greeting=greeting, user=user, files=files)


# ____________________________ download the file ___________________ 

@app.route("/download/<int:file_id>")
def download_file(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    file = conn.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, user["id"])
    ).fetchone()
    conn.close()

    if not file:
        flash("File not found or not yours.", "error")
        return redirect(url_for("dashboard"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        file["stored_name"],
        as_attachment=True,
        download_name=file["filename"]
    )



# ______________________ delete the file ______________________------- 
@app.route("/delete/<int:file_id>")
def delete_file(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    file = conn.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, user["id"])
    ).fetchone()

    if not file:
        conn.close()
        flash("File not found or not yours.", "error")
        return redirect(url_for("dashboard"))

    # Delete from disk
    try:
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"]))
    except FileNotFoundError:
        pass

    # Delete from DB
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()

    flash("File deleted successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    """Clear session and return to the landing page."""
    session.clear()
    return redirect(url_for("index"))

# Entrypoint for local dev
if __name__ == "__main__":
    # Initialize database if it does not exist
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database...")
        init_db()
    else:
        print("[*] Database already exists, skipping init.")

    # Start Flask application
    app.run(host="0.0.0.0", port=5000, debug=True)    
