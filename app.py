"""
Information Security Fall 2025 Lab 4 - Flask Application with AES Encryption
--------------------------------------------------------------------------
Extended to include AES encryption for uploaded files.
Files are encrypted at rest and decrypted when downloaded.
"""
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3, os
from helpers.verify_2fa import require_2fa
import helpers.guard as guard

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "infosec_lab.db")
AES_KEY_FILE = os.path.join(BASE_DIR, "secret_aes.key")

# File uploader setup
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- AES Encryption/Decryption Helpers ----------------
def load_aes_key():
    """Load the AES key from file."""
    if not os.path.exists(AES_KEY_FILE):
        raise FileNotFoundError(f"AES key file not found: {AES_KEY_FILE}")
    with open(AES_KEY_FILE, "rb") as f:
        return f.read()

def encrypt_file_data(data):
    """
    Encrypt file data using AES-256 in CBC mode.
    Returns: IV + ciphertext (concatenated)
    """
    key = load_aes_key()
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Pad data to be multiple of 16 bytes (AES block size)
    pad_length = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_length] * pad_length)
    
    # Encrypt and prepend IV
    ciphertext = cipher.encrypt(padded_data)
    return cipher.iv + ciphertext

def decrypt_file_data(encrypted_data):
    """
    Decrypt file data using AES-256 in CBC mode.
    Input: IV + ciphertext (concatenated)
    Returns: original file data
    """
    key = load_aes_key()
    
    # Extract IV (first 16 bytes) and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    
    # Remove padding
    pad_length = padded_data[-1]
    return padded_data[:-pad_length]


# _______ redirect ____ ____
def redirect_to_dashboard(user):
    if user['role'] == 'basic':
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("dash_admin"))

# ---------------- Database Helpers ----------------
def get_db():
    """Open a connection to SQLite with Row access."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database by executing schema.sql (single source of truth)."""
    schema_path = os.path.join(BASE_DIR, "schema.sql")
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()
            print(schema_sql)
        conn = get_db()
        try:
            conn.executescript(schema_sql)
            conn.commit()
        finally:
            conn.close()
    except FileNotFoundError:
        print(f"Warning: schema.sql not found at {schema_path}")

# Ensure database is initialized at import time
os.makedirs(BASE_DIR, exist_ok=True)

# ____________ log audit __________________ 
def log_audit(user_id, action, target, result):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_logs (actor_andrew_id, action, target, outcome) VALUES (?, ?, ?, ?)',
        (user_id, action, target, result)
    )
    conn.commit()
    conn.close()
    
    
    # ____________------ user otp chain ____________-
def generate_otp_chain(user_id, conn):
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
 
    return True


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
           
            # get user id
            user_id = conn.execute("SELECT id FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()['id']
           
            # make this a function and take it out of here
            # generate OTP chain for the user and store in DB
          
            gen = generate_otp_chain(user_id, conn)
    

            flash(("Registration successful! Please log in.", "success") if gen else ("Registration failed during OTP generation.", "error"))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That Andrew ID is already registered.", "error")
            return render_template("register.html", title="Register", name=name, andrew_id=andrew_id)
        finally:
            conn.commit()
            conn.close()
    return render_template("register.html", title="Register")


# ______ loging  route _____________________________ 
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
            session["verified_2fa"] = False  # Reset 2FA status
           
            return redirect(url_for("two_factor_auth"))
        flash("Invalid Andrew ID or password.", "error")
    return render_template("login.html", title="Login")


# _____________________ 2fa __________________________ 
@app.route("/2fa", methods = ["GET", "POST"] )
def two_factor_auth():
    # chech if the user is logged in with passwored
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # if alread has 2fa, go to the dashborda
    if session.get("verified_2fa"):
        return redirect_to_dashboard(user)
    
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()

        if not entered_otp:
            flash("OTP input is required.", "error")
            return render_template("2fa.html", title="Two-Factor Authentication" )
        
        user_id = session["user_id"]
        import datetime
        # get the current time and create the tolerance window ( of 2 min)
        now = datetime.datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0 )
        tolerence_window = [current_minute - datetime.timedelta(minutes=1), current_minute, current_minute + datetime.timedelta(minutes=1)] 
        timestamps = [int(t.strftime("%Y%m%d%H%M")) for t in tolerence_window]

        # get the OTP from the DB
        conn = get_db()
        # the querry shoudl fetch all the otps for the user in the tolerance window
        query = f"SELECT otp FROM otp_chain WHERE user_id = ? AND timestamp IN ({','.join(['?']*len(timestamps))})"
        params = [user_id] + timestamps
        # feltch all otps in the server 
        otps = conn.execute(query, params).fetchall()
        conn.close()
        # verify if 
        valid_otps = {row['otp'] for row in otps}
        # print(f"[+] Valid OTPs for user {user_id} at times {timestamps}: {valid_otps}")
        user = current_user()
        if entered_otp in valid_otps:
            session["verified_2fa"] = True
            return redirect_to_dashboard(user)
        else:
            flash("Invalid OTP. Please try again.", "error")
            return render_template("2fa.html", title="Two-Factor Authentication")
    return render_template("2fa.html", title="Two-Factor Authentication")


# ________________ show otp _______________________________________- 

@app.route("/show-otp")
def show_otp():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Get current time
    now = datetime.utcnow()
    current_minute = now.replace(second=0, microsecond=0)
    timestamp = int(current_minute.strftime("%Y%m%d%H%M"))
    
    # Get current OTP
    conn = get_db()
    # select someghing form the otp chain to see if it is working
    otp_text = conn.execute("SELECT * FROM otp_chain LIMIT 1").fetchone()
    print(otp_text)

    otp_record = conn.execute(
        "SELECT otp FROM otp_chain WHERE user_id = ? AND timestamp = ?",
        (user["id"], timestamp)
    ).fetchone()

    print(user['id'], timestamp, otp_record)
    conn.close()
    
    if otp_record:
        current_otp = f"{int(otp_record['otp']):06d}"
    else:
        current_otp = "No OTP available"
    
    return render_template("show_otp.html", 
                         title="Current OTP", 
                         user=user, 
                         current_otp=current_otp,
                         timestamp=timestamp)

# ---------------- File Upload with Encryption ----------------
@app.route("/upload", methods=["POST"])
@require_2fa
def upload_file():
    user = current_user()
    print(f"User type: {type(user)}")
    
    if not user:
        return redirect(url_for("login"))
    


    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected", "error")
        return redirect_to_dashboard(user)
    
    # Secure the filename
    original_name = secure_filename(file.filename)
    if original_name == "":
        flash("Invalid file name.", "error")
        return redirect_to_dashboard(user)

    try:
        # Read file data
        file_data = file.read()
        print(f"[+] Original file size: {len(file_data)} bytes")
        
        # Encrypt file data
        encrypted_data = encrypt_file_data(file_data)
        print(f"[+] Encrypted file size: {len(encrypted_data)} bytes")
        
        # Save encrypted file to disk with unique name
        stored_name = f"{user['andrew_id']}_{int(datetime.utcnow().timestamp())}_{original_name}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        
        with open(path, "wb") as f:
            f.write(encrypted_data)

        # Insert data into DB
        conn = get_db()
        conn.execute(
            "INSERT INTO files (user_id, filename, stored_name, size) VALUES (?, ?, ?, ?)",
            (user["id"], user['andrew_id']+original_name, stored_name, len(file_data)),  # Store original file size
        )
        conn.commit()
        conn.close()

        flash("File uploaded and encrypted successfully!", "success")
        print(f"[+] File encrypted and saved as: {stored_name}")
        
    except Exception as e:
        flash(f"Upload failed: {str(e)}", "error")
        print(f"[-] Upload error: {e}")
        
    return redirect_to_dashboard(user)

# ---------------- Dashboard with File List ----------------
@app.route("/dashboard")
@require_2fa
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db()

    files = conn.execute(
        "SELECT * FROM files ORDER BY uploaded_at DESC"
    ).fetchall()
    
    # if user is basic -> fetch only their files
    if user["role"] not in ["data_admin"]:
        files = [f for f in files if f["user_id"] == user["id"]]   

    # If admin -> fetch all users
    if user["role"] in ["user_admin", "data_admin"]:
        users = conn.execute(
            "SELECT id, name, andrew_id, role FROM users ORDER BY id ASC"
        ).fetchall()
    else:
        # Fetch only the current user, but keep consistent format
        users = conn.execute(
            "SELECT id, name, andrew_id, role FROM users WHERE id = ?",
            (user["id"],)
        ).fetchall()
        
    # fetch all logs if the user is admin
    conn.close()
    
    greeting = f"Hello {user['name']}, Welcome to Lab 4 of Information Security course. Enjoy!!!"
    return render_template(
        "dashboard.html",
        title="Dashboard",
        page = 1,
        total_pages = 2,
        greeting=greeting,
        current_user=user,
        files=files,
        users=users
    )

# ---------------- File Download with Decryption ----------------
@app.route("/download/<int:file_id>")
@require_2fa
def download_file(file_id):
    user = current_user()
    print(user)
    if not user:
        return redirect(url_for("login"))



    conn = get_db()
    file = conn.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()
    conn.close()

    if not file:
        flash("File not found or not yours.", "error")
        return redirect_to_dashboard(user)
    
    
    # use gurard to restrict access to download your own file except for admins
    isown = (file['user_id'] == user['id'])

    can_download = guard.guard('download_own_file' if isown else 'download_any_file', target=file['filename'])

    if not can_download:
        flash("You do not have permission to download this file.", "error")
        return redirect_to_dashboard(user)

    try:
        # Read encrypted file from disk
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"])
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        print(f"[+] Reading encrypted file: {file['stored_name']} ({len(encrypted_data)} bytes)")
        
        # Decrypt file data
        decrypted_data = decrypt_file_data(encrypted_data)
        print(f"[+] Decrypted to: {len(decrypted_data)} bytes")
        
        # Return decrypted file to user
        return Response(
            decrypted_data,
            headers={
                'Content-Disposition': f'attachment; filename="{file["filename"]}"',
                'Content-Type': 'application/octet-stream'
            }
        )
        
    except Exception as e:
        flash(f"Download failed: {str(e)}", "error")
        print(f"[-] Download error: {e}")
        return redirect_to_dashboard(user)

# ---------------- File Delete ----------------
@app.route("/delete/<int:file_id>")
@require_2fa
def delete_file(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    

    # use guarad to restrict access to delete your own files
    

    conn = get_db()
    file = conn.execute( 
        f"SELECT * FROM files WHERE id = ? ",
        (file_id ,)
    ).fetchone()

    if not file:
        conn.close()
        flash("File not found or not yours.", "error")
        return redirect_to_dashboard(user)

    # chek if is owner
    is_owner = (file['user_id'] == user['id'])
    target_filename = file['filename']

    # check if the user can delete the file
    can_delete = guard.guard("delete_own_file" if is_owner else "delete_any_file", target=target_filename)  

    if not can_delete:
        flash("You do not have permission to delete this file.", "error")
        conn.close()
        return redirect_to_dashboard(user)
    
    # Delete from disk
    try:
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"]))
        print(f"[+] Deleted encrypted file: {file['stored_name']}")
    except FileNotFoundError:
        print(f"[-] File not found on disk: {file['stored_name']}")
        pass

    # Delete from DB
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()

    flash("File deleted successfully.", "success")
    return redirect_to_dashboard(user)


# =============== AUDIT LOGS ROUTE ======================
@app.route("/dash_admin")
@require_2fa
def dash_admin():
    user = current_user()
    
    
    if not user:
        return redirect(url_for("login"))
    
    conn = get_db()
    
    
    # other thing requiered for the dashboard
    files = conn.execute(
        "SELECT * FROM files ORDER BY uploaded_at DESC"
    ).fetchall()
    
    # if user is basic -> fetch only their files
    if user["role"] not in ["data_admin"]:
        files = [f for f in files if f["user_id"] == user["id"]]   

    # If admin -> fetch all users
    if user["role"] in ["user_admin", "data_admin"]:
        users = conn.execute(
            "SELECT id, name, andrew_id, role FROM users ORDER BY id ASC"
        ).fetchall()
    else:
        # Fetch only the current user, but keep consistent format
        users = conn.execute(
            "SELECT id, name, andrew_id, role FROM users WHERE id = ?",
            (user["id"],)
        ).fetchall()

    # Permission check
    can_view = guard.guard("read_log_file", target="audit_logs")
    print(f"[+] Audit log access check for user {user['role']}: {can_view}")
    if not can_view:
        print(f"[+] Audit log access check for user {user['role']}: {can_view}")
        flash("You do not have permission to view audit logs.", "error")
        return redirect_to_dashboard(user)

    # --- Sorting and Pagination ---
    sort_by = request.args.get("sort_by", "created_at")
    order = request.args.get("order", "desc")
    page = int(request.args.get("page", 1))
    per_page = 10
    offset = (page - 1) * per_page

    # Validate input
    valid_sort_columns = ["created_at", "actor_andrew_id", "action", "target", "outcome"]
    if sort_by not in valid_sort_columns:
        sort_by = "created_at"
    if order.lower() not in ["asc", "desc"]:
        order = "desc"

    # --- Fetch Logs ---

    logs = conn.execute(
        f"""
        SELECT created_at, actor_andrew_id, action, target, outcome
        FROM audit_logs
        ORDER BY {sort_by} {order}
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()

    total_logs = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    conn.close()

    total_pages = (total_logs + per_page - 1) // per_page

    # --- Render Dashboard with active audit tab ---
    return render_template(
        "dashboard.html",
        title="Audit Logs",
        current_user=user,
        logs=logs,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        order=order,
        active_tab="audit-section",
        files=files,
        users=users,
    )

# _______________________ USERS ROUTES ___________________________

# change password route
@app.route("/change_password", methods=["POST"])
@require_2fa
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check permission
    can_change = guard.guard("change_password", target=user['andrew_id'])
    if not can_change:
        flash("You do not have permission to change your password.", "error")
        return redirect_to_dashboard(user)
    
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        flash("All password fields are required.", "error")
        return redirect_to_dashboard(user)

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect_to_dashboard(user)

    if not check_password_hash(user["password"], current_password):
        flash("Current password is incorrect.", "error")
        return redirect_to_dashboard(user)

    hashed_new_password = generate_password_hash(new_password)

    conn = get_db()
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hashed_new_password, user["id"])
    )
    conn.commit()
    conn.close()

    flash("Password changed successfully.", "success")
    return redirect_to_dashboard(user)

# asign role to user route
@app.route("/assign_role/<target_andrew_id>", methods=["POST"])
@require_2fa
def assign_role(target_andrew_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check permission
    can_assign = guard.guard("assign_role", target=target_andrew_id)
    
    if not can_assign:
        flash("Assign role denied.", "error")
        return redirect_to_dashboard(user)
    
    new_role = request.form.get("role", "basic")
    if new_role not in ["basic", "user_admin", "data_admin"]:
        flash("Invalid role selected.", "error")
        return redirect_to_dashboard(user)

    conn = get_db()
    target_user = conn.execute(
        "SELECT * FROM users WHERE andrew_id = ?",
        (target_andrew_id,)
    ).fetchone()

    if not target_user:
        conn.close()
        flash("User not found.", "error")
        return redirect_to_dashboard(user)

    conn.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, target_user["id"])
    )
    conn.commit()
    conn.close()

    flash(f"Role of user {target_andrew_id} updated to {new_role}.", "success")
    return redirect_to_dashboard(user)


# change username route 
@app.route("/change_username/<target_andrew_id>", methods=["POST"])
@require_2fa
def change_username(target_andrew_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check permission
    can_change = guard.guard("change_username", target=target_andrew_id)
    if not can_change:
        flash("You do not have permission to change usernames.", "error")
        return redirect_to_dashboard(user)
    
    new_name = request.form.get("name", "").strip()
    if not new_name:
        flash("Name cannot be empty.", "error")
        return redirect_to_dashboard(user)

    conn = get_db()
    target_user = conn.execute(
        "SELECT * FROM users WHERE andrew_id = ?",
        (target_andrew_id,)
    ).fetchone()

    if not target_user:
        conn.close()
        flash("User not found.", "error")
        return redirect_to_dashboard(user)

    conn.execute(
        "UPDATE users SET name = ? WHERE id = ?",
        (new_name, target_user["id"])
    )
    conn.commit()
    conn.close()

    flash(f"Name of user {target_andrew_id} updated to {new_name}.", "success")
    return redirect_to_dashboard(user)


# _______ delete user using the guard for auth ___________________________
@app.route("/delete_user/<target_andrew_id>")
@require_2fa
def delete_user(target_andrew_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check permission
    can_delete = guard.guard("delete_user", target=target_andrew_id, forbid_self_delete=True)
    if not can_delete:
        flash("You do not have permission to delete this user.", "error")
        return redirect_to_dashboard(user)
    
    conn = get_db()
    target_user = conn.execute(
        "SELECT * FROM users WHERE andrew_id = ?",
        (target_andrew_id,)
    ).fetchone()

    if not target_user:
        conn.close()
        flash("User not found.", "error")
        return redirect_to_dashboard(user)

    # Delete user's files from disk
    user_files = conn.execute(
        "SELECT * FROM files WHERE user_id = ?",
        (target_user["id"],)
    ).fetchall()

    for file in user_files:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"]))
            print(f"[+] Deleted encrypted file: {file['stored_name']}")
        except FileNotFoundError:
            print(f"[-] File not found on disk: {file['stored_name']}")
            pass

    # Delete user's files from DB
    conn.execute("DELETE FROM files WHERE user_id = ?", (target_user["id"],))
    
    # Delete user from DB
    conn.execute("DELETE FROM users WHERE id = ?", (target_user["id"],))
    conn.commit()
    conn.close()

    flash(f"User {target_andrew_id} and their files have been deleted.", "success")
    return redirect_to_dashboard(user)

# ____________ create user ________-- 
@app.route("/create_user", methods=["POST"])
@require_2fa
def create_user():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check permission
    can_create = guard.guard("create_user", target="new_user")
    if not can_create:
        flash("You do not have permission to create users.", "error")
        return redirect_to_dashboard(user)
    
    name = request.form.get("name", "").strip()
    andrew_id = request.form.get("andrew_id", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "basic")

    if not name or not andrew_id or not password:
        flash("All fields are required to create a user.", "error")
        return redirect_to_dashboard(user)

    hashed_password = generate_password_hash(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (name, andrew_id, password, role) VALUES (?, ?, ?, ?)",
            (name, andrew_id, hashed_password, role)
        )
        
        # the the user assigned id
        user_id = conn.execute("SELECT id FROM users WHERE andrew_id = ?", (andrew_id,)).fetchone()['id']
        # generate the otp chain for the new user
        generate_otp_chain(user_id, conn)   
        
        
        conn.commit()
        flash(f"User {andrew_id} created successfully.", "success")
    except sqlite3.IntegrityError:
        flash("That Andrew ID is already registered.", "error")
    finally:
        conn.close()

    return redirect_to_dashboard(user)


# _____________--- logout ---______________________________

@app.route("/logout")
def logout():
    """Clear session and return to the landing page."""
    session.clear()
    return redirect(url_for("index"))

# ___________--- security hooks ---________________________
@app.before_request
def enforce_https_in_production():
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "http") == "https":
        return
    if os.environ.get("FLASK_ENV") == "production":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)  

@app.after_request
def set_security_headers(res):
    res.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["X-XSS-Protection"] = "1; mode=block"
    return res


# Entrypoint for local dev
if __name__ == "__main__":
    # Initialize database if it does not exist
    if not os.path.exists(DB_FILE):
        print("[*] Initializing database.")
        init_db()
    else:
        print("[*] Database already exists, skipping init.")
    
    # Check if AES key exists
    if not os.path.exists(AES_KEY_FILE):
        print(f"[!] AES key not found at {AES_KEY_FILE}")
        print("[!] Please run generate_key.py first to create the AES key")
    else:
        print(f"[+] AES key found at {AES_KEY_FILE}")
        
        
    cert_dir = os.path.join(BASE_DIR, "certs")
    cert_filename = os.path.join(cert_dir, "dev-cert.pem")
    key_filename = os.path.join(cert_dir, "dev-key.pem")
    
    if not os.path.exists(cert_filename) or not os.path.exists(key_filename):
        print(f"[!] Development SSL certificates not found in {cert_dir}")
        print("[!] Please generate self-signed certificates for HTTPS support in development")
    else:
        print(f"[+] Development SSL certificates found in {cert_dir}")
    

    # Start Flask application
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=(cert_filename, key_filename))
      