from gevent import monkey; monkey.patch_all()
import ssl
import json
import os
import time
import hashlib
from flask import Flask, make_response, render_template, redirect, url_for, request, session, jsonify, send_from_directory, abort
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_session import Session
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from threading import Thread
import random
import string
import logging, sys
import socket
import bcrypt
from datetime import datetime
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import requests

# Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(__file__), "flask_session")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SECURE"] = True # Change to True in production / false otherwise
app.config["SESSION_COOKIE_HTTPONLY"] = True 
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" 

for h in list(app.logger.handlers):
    app.logger.removeHandler(h)
logging.getLogger('gevent.ssl').setLevel(logging.CRITICAL)
logging.getLogger('engineio').setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger("werkzeug").disabled = True

@app.errorhandler(404)
def silent_404(e):
    return "", 404

Session(app)

# User Status  
user_status = {}

# RSA Keys
def load_rsa_keys():
    try:
        with open("private_key.pem", "rb") as f:
            key_data = f.read()
        if b"-----BEGIN PRIVATE KEY-----" not in key_data:
            raise ValueError("Invalid Key Format")
        private_key = serialization.load_pem_private_key(key_data, password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    except FileNotFoundError:
        print("[WARNING] RSA keys not found. Generating new keys...")
        generate_rsa_keys()
        return load_rsa_keys()
    except Exception as e:
        print(f"[ERROR] Failed to load private key: {e}")
        raise e

def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_key = private_key.public_key()
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("private_key.pem", "wb") as f:
            f.write(private_key_bytes)
        with open("public_key.pem", "wb") as f:
            f.write(public_key_bytes)
        print("[SUCCESS] RSA keys generated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to generate RSA keys: {e}")

# RSA keys loading
try:
    private_key, rsa_public_key = load_rsa_keys()
except FileNotFoundError:
    print("[WARNING] RSA keys not found. Please run ./reset_project.sh to generate them.")
    exit(1)

 # AES key specifically for logging messages
log_aes_key_file = 'log_aes_key.bin'

if not os.path.exists(log_aes_key_file):
    with open(log_aes_key_file, 'wb') as f:
        f.write(os.urandom(32))

with open(log_aes_key_file, 'rb') as f:
    log_aes_key = f.read()

# RSA Key Logging
def get_rsa_fingerprint(key):
    return hashlib.sha256(
        key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()

# AES-256 Encryption
session_keys = {}

@app.route("/generate_aes_key", methods=["POST"])
def generate_aes_key():
    username = session.get("username")
    if not username:
        return jsonify({"success": False, "message": "User not authenticated."})
    aes_key = os.urandom(32)
    session_keys[username] = aes_key
    try:
        encrypted_aes_key = rsa_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        if decrypted_aes_key != aes_key:
            return jsonify({"success": False, "message": "AES Key verification failed."})
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode()

        return jsonify({
            "success": True,
            "encrypted_aes_key": encrypted_key_b64
        })
    except Exception as e:
        print(f"[ERROR] AES Key encryption failed: {e}")
        return jsonify({"success": False, "message": "AES Key encryption failed."})

def encrypt_message(data, aes_key):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + encrypted_data).decode('utf-8')

def decrypt_message(encrypted_message_b64, aes_key, binary=False):
    try:
        encrypted_message = base64.b64decode(encrypted_message_b64)
        nonce = encrypted_message[:12]
        ciphertext = encrypted_message[12:]
        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        if binary:
            return decrypted_data
        else:
            return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"[ERROR] AES Decryption failed: {e}")
        return "[ERROR] Unable to decrypt message."

@app.route("/get_private_key", methods=["POST"])
def get_private_key():
    try:
        with open("private_key.pem", "r") as f:
            private_key = f.read().strip()
        private_key = "\n".join(line.strip() for line in private_key.strip().splitlines())
        if not private_key.startswith("-----BEGIN PRIVATE KEY-----") or \
           not private_key.endswith("-----END PRIVATE KEY-----"):
            return jsonify({"success": False, "message": "Private key invalid."})
        return jsonify({"success": True, "private_key": private_key})
    except Exception as e:
        print(f"[ERROR] Failed to retrieve private key: {e}")
        return jsonify({"success": False, "message": "Failed to retrieve private key."})

# Uploading files
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB file size limit

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"success": False, "message": "File size exceeds 8MB limit."}), 413

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# logging w/ filtering
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("gevent.ssl").setLevel(logging.ERROR)
logging.getLogger("engineio.server").setLevel(logging.CRITICAL)
logging.getLogger("socketio").setLevel(logging.DEBUG)
logging.getLogger("engineio").setLevel(logging.DEBUG)

LOGS_FOLDER = "chat_logs"
if not os.path.exists(LOGS_FOLDER):
    os.makedirs(LOGS_FOLDER)

# Initialize WebSocket with Flask-SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="gevent",
    path="/socket.io",       
    transports=["websocket"],
    ping_timeout=20,
    ping_interval=5,
)

# SSL Setup
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain("cert.pem", "key.pem")
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2+
ssl_context.set_ciphers("HIGH:!aNULL:!MD5:!RC4")

# limit ssl errors atleats 1 per second
last_ssl_error_time = 0

# User database
USER_DB = "users.json"

# Store the last message timestamp for each user
user_last_message_time = {}

# Active rooms
rooms = {}

# Active users
connected_users = {}

# Login page brute force prevention
failed_login_attempts = {}

# --------------------------- Functions ----------------
def verify_captcha(token, remote_ip=None):
    payload = {
        "secret":  os.environ["RECAPTCHA_SECRET"],
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip
    try:
        r = requests.post("https://www.google.com/recaptcha/api/siteverify",
                          data=payload, timeout=3)
        r.raise_for_status()
        data = r.json()
        return data.get("success", False)
    except Exception as e:
        app.logger.warning("reCAPTCHA verification error: %s", e)
        return False

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def broadcast_presence():
    socketio.emit("presence_update", list(user_status.values()), broadcast=True)

IP_BLOCK_DURATION = 300
MAX_FAILED_ATTEMPTS = 3

def is_ip_blocked(ip):
    if ip in failed_login_attempts:
        attempts, block_start = failed_login_attempts[ip]
        if attempts >= MAX_FAILED_ATTEMPTS and time.time() - block_start < IP_BLOCK_DURATION:
            abort(429)          
        elif attempts >= MAX_FAILED_ATTEMPTS:
            del failed_login_attempts[ip] 
    return False

@app.errorhandler(429)
def ratelimit_handler(e):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(success=False,
                       message="Too many failed attempts – wait 5 min"), 429
    return render_template("login.html",
                           error="Too many failed attempts. Please wait 5 min"), 429

def record_failed_attempt(ip):
    if ip in failed_login_attempts:
        failed_login_attempts[ip][0] += 1
    else:
        failed_login_attempts[ip] = [1, time.time()]

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def encrypt_log_entry(entry, aes_key):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_entry = aesgcm.encrypt(nonce, entry.encode('utf-8'), None)
    return base64.b64encode(nonce + encrypted_entry).decode('utf-8')

def decrypt_log_entry(encrypted_entry_b64, aes_key):
    encrypted_data = base64.b64decode(encrypted_entry_b64)
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

def log_message(roomId, username, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {username}: {msg}"
    encrypted_entry = encrypt_log_entry(log_entry, log_aes_key)
    log_file = os.path.join(LOGS_FOLDER, f"{roomId}.enc")
    with open(log_file, "a") as file:
        file.write(encrypted_entry + "\n")

def generate_room():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=4))

def load_users():
    if os.path.exists(USER_DB):
        try:
            with open(USER_DB, "r") as file:
                data = file.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except json.JSONDecodeError:
            return {}
    return {}

def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def monitor_inactivity():
    while True:
        now = time.time()
        for sid, last_msg_time in list(user_last_message_time.items()):
            if now - last_msg_time > 1800:   
                username = session.get("username", "Unknown")
                roomId = session.get("room", "Unknown")
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"[INFO] Forcefully disconnected user '{username}' in room '{roomId}' due to inactivity.")
                socketio.emit("force_disconnect", {"msg": "You have been disconnected due to inactivity."}, room=sid)
                socketio.server.disconnect(sid)
                del user_last_message_time[sid]
                if roomId in rooms and not rooms[roomId]["users"]:
                    remove_room(roomId)
        time.sleep(5)

Thread(target=monitor_inactivity, daemon=True).start()
user_last_message_time = {}

def remove_room(roomId):
    if roomId in rooms:
        del rooms[roomId]
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Room '{roomId}' has been removed.")

# --------------------------- Routes -------------------
@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return redirect(url_for("dashboard_page"))

@app.route("/dashboard")
def dashboard_page():
    if not session.get("username"):
        return redirect(url_for("login_page"))
    room_code = request.args.get("roomId", "").strip().upper()
    if not room_code:
        return render_template("dashboard.html", roomId="None")
    return render_template("dashboard.html", roomId=room_code)

@app.route("/<code>")
def room_shortcut(code):
    if len(code) == 4 and code.isalnum():
        return redirect(url_for("dashboard_page", roomId=code.upper()))
    abort(404)

@app.route("/<code>/")
def room_shortcut_slash(code):
    if len(code) == 4 and code.isalnum():
        return redirect(url_for("dashboard_page", roomId=code.upper()), code=302)
    abort(404)

logging.getLogger('werkzeug').setLevel(logging.ERROR)

@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    try:
        with open("public_key.pem", "r") as f:
            public_key = f.read().strip()
        return jsonify({"success": True, "public_key": public_key})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part in request"}), 400
    file = request.files['file']
    room_id = request.form.get('roomId')
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_data = file.read()
        encrypted_data = encrypt_message(file_data, room_aes_keys.get(room_id))
        with open(filepath, "w") as f:
            f.write(encrypted_data)
        return jsonify({"success": True, "filename": filename}), 200
    return jsonify({"success": False, "message": "Something went wrong"}), 500

@app.route("/download/<filename>", methods=["POST"])
def download_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    room_id = request.json.get("roomId")
    aes_key = room_aes_keys.get(room_id)
    if not aes_key:
        return jsonify({"success": False, "message": "Room AES key missing"}), 400
    with open(file_path, "rb") as f:
        encrypted_data_b64 = f.read().decode('utf-8')
    decrypted_data = decrypt_message(encrypted_data_b64, aes_key, binary=True) 
    mime_type = "image/jpeg" if filename.lower().endswith(".jpg") else "image/png"
    response = make_response(decrypted_data)
    response.headers['Content-Type'] = mime_type
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    room_id = request.args.get("roomId")
    aes_key = room_aes_keys.get(room_id)
    if not aes_key:
        return jsonify({"success": False, "message": "Room AES key missing"}), 400
    try:
        with open(file_path, "rb") as f:
            encrypted_data_b64 = f.read().decode('utf-8')
        decrypted_data = decrypt_message(encrypted_data_b64, aes_key, binary=True)
        file_ext = filename.rsplit('.', 1)[1].lower()
        mime_type = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "pdf": "application/pdf"
        }.get(file_ext, "application/octet-stream")
        response = make_response(decrypted_data)
        response.headers.set('Content-Type', mime_type)
        response.headers.set('Content-Disposition', 'inline', filename=filename)
        return response
    except Exception as e:
        print(f"[ERROR] File serving failed: {e}")
        return jsonify({"success": False, "message": "Failed to serve file."}), 500

# Generate AES key per room
room_aes_keys = {}

@app.route("/get_room_aes_key/<room_id>", methods=["POST"])
def get_room_aes_key(room_id):
    username = session.get("username")
    if not username:
        return jsonify({"success": False, "message": "User not authenticated."}), 401
    user_public_key_pem = request.json.get("user_public_key")
    if not user_public_key_pem:
        return jsonify({"success": False, "message": "User public key missing."}), 400
    try:
        user_public_key = serialization.load_pem_public_key(user_public_key_pem.encode())
        aes_key = room_aes_keys.get(room_id)
        if not aes_key:
            return jsonify({"success": False, "message": "Room AES key not found."}), 404
        encrypted_aes_key = user_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode()
        return jsonify({"success": True, "encrypted_room_aes_key": encrypted_key_b64})
    except Exception as e:
        print(f"[ERROR] Failed to encrypt AES key: {e}")
        return jsonify({"success": False, "message": "AES key encryption failed."}), 500

@app.route("/create-room", methods=["POST"])
def create_room():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room_code = generate_room()
    while room_code in rooms:
        room_code = generate_room()
    aes_key = os.urandom(32)
    room_aes_keys[room_code] = aes_key
    rooms[room_code] = {"users": []}
    print(f"[INFO] Created room {room_code}")
    return jsonify({"success": True, "roomId": room_code})

@app.route("/join-room")
def join_room_route():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room_code = request.args.get("room", "").strip().upper()
    if not room_code or room_code not in rooms:
        return redirect(url_for("dashboard_page"))
    return redirect(f"/dashboard?roomId={room_code}")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    ip = get_client_ip()
    print(f"[INFO] Login page visit from IP: {ip}")
    if is_ip_blocked(ip):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "Too many failed attempts. Try again in 5 minutes."})
        return render_template("login.html", error="Too many failed attempts. Try again later.")
    if request.method == "GET":
        new = request.args.get("new") == "1"
        return render_template("login.html", new=new)
    if request.method == "POST":
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            username = request.form.get("username")
            password = request.form.get("password")
            users = load_users()
            if username in users and verify_password(password, users[username]):
                print(f"[INFO] Successful login for {username}, {ip}")
                session["username"] = username
                if ip in failed_login_attempts:
                    del failed_login_attempts[ip]
                return jsonify({"success": True})
            print(f"[INFO] Failed login for {username}, {ip}")
            record_failed_attempt(ip)
            return jsonify({"success": False, "message": "Invalid credentials"})
        # Fallback for non-AJAX login
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"[INFO] Received form credentials - Username: {username}, {ip}")
        users = load_users()
        if username in users and verify_password(password, users[username]):
            print(f"[INFO] Successful login for {username} (form), {ip}")
            session["username"] = username
            return redirect(url_for("dashboard_page"))
        print(f"[INFO] Failed login (form) for {username}, {ip}")
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    site_key = os.environ["RECAPTCHA_SITE"]
    if request.method == "POST":
        token = request.form.get("g-recaptcha-response")
        if not verify_captcha(token, get_client_ip()):
            return render_template("register.html",
                                   site_key=site_key,
                                   error="Captcha failed — please try again.")
        username = request.form["username"].strip()
        password = request.form["password"]
        users = load_users()
        if username in users:
            return render_template("register.html",
                                   site_key=site_key,
                                   error="Username already taken")
        users[username] = hash_password(password)
        save_users(users)
        return redirect(url_for("login_page", new=1))
    return render_template("register.html", site_key=site_key)

@app.route("/logout")
def logout():
    username = session['username']
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [LOGOUT] {username} logged out.")
    session.pop("username", None)
    return redirect(url_for("login_page"))

@app.route('/favicon.ico')
def favicon():
    return '', 204
# ----------------------------- WebSocket Events -----
@socketio.on("connect")
def handle_connect():
    print(f"[INFO] New Connection SID: {request.sid}")
    ip = get_client_ip()
    if "username" not in session:
        disconnect()

@socketio.on("authenticate")
def handle_auth(data):
    username = data.get("username")
    user_status[request.sid] = {"user": username, "state": "online"}
    broadcast_presence()

@socketio.on("typing")
def handle_typing(data):
    room_id = data.get("roomId")
    if room_id:
        emit("typing", data, room=room_id, include_self=False)

def broadcast_room_roster(roomId):
    names = rooms[roomId]["users"]
    socketio.emit("roster_update", {"roomId": roomId, "users": names}, room=roomId)

@socketio.on("join")
def handle_join(data):
    roomId = data.get("roomId", "").strip().upper()
    username = session.get("username", "Guest")
    if roomId in rooms:
        join_room(roomId)
        if username not in rooms[roomId]["users"]:
            rooms[roomId]["users"].append(username)
        emit("user_joined", {"msg": f"{username} joined the chat"}, room=roomId)
        broadcast_room_roster(roomId)
    else:
        emit("room_invalid", {"msg": f"Room '{roomId}' no longer exists."}, room=request.sid)

@socketio.on("message")
def handle_message(data):
    user = session.get("username", "Guest")
    roomId = data.get("roomId", "").strip().upper()
    if roomId not in rooms:
        emit("room_invalid", {"msg": f"Room '{roomId}' no longer exists."}, room=request.sid)
        return
    encrypted_message = data.get("msg", "")
    socketio.emit("message", {"user": user, "msg": encrypted_message}, room=roomId)
    log_message(roomId, user, encrypted_message)

@socketio.on("disconnect")
def handle_disconnect():
    user_status.pop(request.sid, None)
    broadcast_presence()

@socketio.on("leave")
def handle_leave(data):
    username = data.get("user", "Guest")
    roomId   = data.get("roomId", "").strip().upper()
    if roomId in rooms and username in rooms[roomId]["users"]:
        rooms[roomId]["users"].remove(username)
        emit("user_left", {"msg": f"{username} left"}, room=roomId)
        broadcast_room_roster(roomId)     

@socketio.on_error_default
def websocket_error_handler(e):
    if isinstance(e, ssl.SSLError) and "HTTP_REQUEST" in str(e):
        return 

@socketio.on("heartbeat")
def heartbeat(data):
    if request.sid in user_status:
        user_status[request.sid]["last"] = time.time()

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"[ERROR] {str(e)}")
    if request.content_type and "application/json" in request.content_type:
        return jsonify({"success": False, "message": "Internal server error"}), 500
    return make_response("An internal error occurred.", 500)

# Custom Gevent WSGIServer
class SecureWSGIServer(WSGIServer):
    def wrap_socket_and_handle(self, client_socket, address):
        global last_ssl_error_time
        try:
            peek = client_socket.recv(5, socket.MSG_PEEK) 
            if peek.startswith(b"GET /") and not (b"/socket.io/" in peek or b"/dashboard" in peek):
                now = time.time()
                if now - last_ssl_error_time > 1: 
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{timestamp}] [SECURITY] Dropped invalid HTTP request on HTTPS socket.")
                    last_ssl_error_time = now
                client_socket.close()
                return
        
            super().wrap_socket_and_handle(client_socket, address)
        except Exception as e:
            now = time.time()
            if now - last_ssl_error_time > 1: 
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}][SECURITY] SSL Error: {e}")
                last_ssl_error_time = now
            client_socket.close()

@app.route("/clear_keys_cache", methods=["POST"])
def clear_keys_cache():
    print("[INFO] Forcing client-side key refresh...")
    return jsonify({"success": True, "message": "Client cache refresh triggered."})

@app.before_request
def refresh_session():
    session.modified = True

@app.route("/ping")
def ping():
    return jsonify({"status": "alive"}), 200

# ----- Run Flask Server -----
if __name__ == "__main__":
    print("[INFO] Flask server started and accepting HTTPS traffic on port 5000...")
    http_server = SecureWSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
