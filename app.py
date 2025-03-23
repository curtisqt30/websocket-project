import ssl
import json
import os
import time
import hashlib
from flask import Flask, make_response, render_template, redirect, url_for, request, session, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_session import Session
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from threading import Thread
import random
import string
import logging
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

# Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(__file__), "flask_session")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True 
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" 
Session(app)

# RSA Keys
def load_rsa_keys():
    try:
        with open("private_key.pem", "rb") as f:
            key_data = f.read()
            # print(f"[DEBUG] Raw Private Key Data (Length: {len(key_data)})")
        if b"-----BEGIN PRIVATE KEY-----" not in key_data:
            # print("[ERROR] Malformed Private Key. Detected old PKCS#1 format or corrupted data.")
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

# print(f"[DEBUG] RSA Public Key Fingerprint: {get_rsa_fingerprint(rsa_public_key)}")

# AES-256 Encryption
session_keys = {}

@app.route("/generate_aes_key", methods=["POST"])
def generate_aes_key():
    username = session.get("username")
    if not username:
        return jsonify({"success": False, "message": "User not authenticated."})
    aes_key = os.urandom(32)
    session_keys[username] = aes_key
    # print(f"[DEBUG] Raw AES Key (32 bytes): {aes_key.hex()}")
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
            # print("[ERROR] AES Key Mismatch! Corruption detected before transmission.")
            return jsonify({"success": False, "message": "AES Key verification failed."})
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode()
        # print(f"[DEBUG] Encrypted AES Key (Length: {len(encrypted_key_b64)}): {encrypted_key_b64}")

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
        # print(f"[DEBUG] Private Key Content (Length: {len(private_key)})")
        # print(private_key)
        private_key = "\n".join(line.strip() for line in private_key.strip().splitlines())
        if not private_key.startswith("-----BEGIN PRIVATE KEY-----") or \
           not private_key.endswith("-----END PRIVATE KEY-----"):
            # print("[ERROR] Private key format invalid or incomplete.")
            return jsonify({"success": False, "message": "Private key invalid."})
        # print("[DEBUG] Private Key Retrieved Successfully.")
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
socketio = SocketIO(app, 
                    cors_allowed_origins="*", 
                    path="/socket.io/", 
                    async_mode="gevent",
                    ping_timeout=20,
                    ping_interval=5 
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

# Active clients
# connected_clients = set()

# Store the last message timestamp for each user
user_last_message_time = {}

# Active rooms
rooms = {}

# Login page brute force prevention
failed_login_attempts = {}

IP_BLOCK_DURATION = 300
MAX_FAILED_ATEMPTS = 3

# --------------------------- Functions ----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file provided"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "message": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        aes_key = session_keys.get(session.get("username"))
        if not aes_key:
            return jsonify({"success": False, "message": "AES key missing"}), 400
        try:
            file_data = file.read()
            encrypted_data_b64 = encrypt_message(file_data, aes_key)
            with open(os.path.join(app.config["UPLOAD_FOLDER"], filename), "wb") as f:
                f.write(encrypted_data_b64.encode('utf-8'))  # Store encrypted file as Base64 string
            return jsonify({"success": True, "filename": filename})
        except Exception as e:
            print(f"[ERROR] File encryption failed: {e}")
            return jsonify({"success": False, "message": "File upload failed."})

@app.route("/download/<filename>")
def download_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    aes_key = session_keys.get(session.get("username"))
    if not aes_key:
        return jsonify({"success": False, "message": "AES key missing"}), 400
    with open(file_path, "rb") as f:
        encrypted_data_b64 = f.read().decode('utf-8')
    decrypted_data = decrypt_message(encrypted_data_b64, aes_key)
    response = make_response(base64.b64decode(decrypted_data))
    mime_type = "image/jpeg" if filename.lower().endswith(".jpg") else "image/png"
    response.headers['Content-Type'] = mime_type
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    aes_key = session_keys.get(session.get("username"))
    if not aes_key:
        return jsonify({"success": False, "message": "AES key missing"}), 400
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

def is_ip_blocked(ip):
    if ip in failed_login_attempts:
        attempts, block_start = failed_login_attempts[ip]
        if attempts >= MAX_FAILED_ATEMPTS:
            if time.time() - block_start < IP_BLOCK_DURATION:
                remaining_time = int(IP_BLOCK_DURATION - (time.time() - block_start))
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"[SECURITY] IP '{ip}' is blocked for {remaining_time} seconds due to {attempts} failed attempts.")
                return True
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"[INFO] IP '{ip}' block expired. Removing from blocked list.")
                del failed_login_attempts[ip]
    return False

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
        # print("[DEBUG] Session missing username, redirecting...")
        return redirect(url_for("login_page"))
    room_code = request.args.get("roomId", "").strip().upper()
    if not room_code:
        return render_template("dashboard.html", roomId="None")
    return render_template("dashboard.html", roomId=room_code)

@app.route("/create-room", methods=["POST"])
def create_room():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room_code = generate_room()
    while room_code in rooms:
        room_code = generate_room()
    rooms[room_code] = {"users": []}
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Created room {room_code}")
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
    # print("Current session content:", dict(session))
    ip = get_client_ip()
    if is_ip_blocked(ip):
        return jsonify({
            "success": False,
            "message": "Too many failed attempts. Try again in 5 minutes."
        })
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users and verify_password(password, users[username]):
            session["username"] = username
            session.modified = True
            ip = get_client_ip()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [LOGIN] {username} successfully logged in. (IP: {ip})")
            # print(f"[DEBUG] Session after login: {session.get('username')}")
            if ip in failed_login_attempts:
                del failed_login_attempts[ip]
            return jsonify({"success": True})
        record_failed_attempt(ip)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [FAILED LOGIN] IP: {ip} | Failed Attempt #{failed_login_attempts[ip][0]}")
        return jsonify({"success": False, "message": "Invalid credentials"})
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                  f"[INFO] Registration failed: Username '{username}' is already taken.")
            return render_template("register.html", error="Username already taken")
        users[username] = hash_password(password)
        save_users(users)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
              f"[INFO] New user registered successfully: '{username}'")
        return redirect(url_for("login_page"))
    return render_template("register.html")


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
    # print(f"[DEBUG] Connection Attempt Received from {ip}")
    if "username" not in session:
        # print(f"[DEBUG] Session missing username - rejecting connection")
        disconnect()
    # else:
    #     # print(f"[DEBUG] Connection Successful for {session['username']}")
    #     connected_clients.add(request.sid)

@socketio.on("authenticate")
def handle_auth(data):
    username = data.get("username")
    # print(f"[DEBUG] Auth attempt with username: {username}")
    if not username:
        print("No username provided, disconnecting.")
        disconnect()
        return

@socketio.on("join")
def handle_join(data):
    roomId = data.get("roomId", "").strip().upper()
    username = session.get("username", "Guest")

    if roomId in rooms:
        join_room(roomId)
        rooms[roomId]["users"].append(username)
        # print(f"[DEBUG] Room Data After Join: {rooms}")
        emit("user_joined", {"msg": f"{username} joined the chat"}, room=roomId)
    else:
        print(f"[ERROR] Room {roomId} doesn't exist or was deleted.")
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
    if "username" in session:
        username = session['username']
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [USER DISCONNECTED] {username}")
        for roomId, data in rooms.items():
            if username in data["users"]:
                data["users"].remove(username)
                emit("user_left", {"msg": f"{username} has left the chat"}, room=roomId)

@socketio.on("leave")
def handle_leave(data):
    username = data.get("user", "Guest")
    roomId = data.get("roomId", "").strip().upper()
    if roomId in rooms and username in rooms[roomId]["users"]:
        rooms[roomId]["users"].remove(username)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ROOM={roomId}] {username} left the chat.")
        emit("user_left", {"msg": f"{username} has left the chat"}, room=roomId)
    else:
        print(f"[ERROR] Room {roomId} doesn't exist or user {username} not in room.")
        emit("room_invalid", {"msg": f"Room '{roomId}' no longer exists. Redirecting you to the dashboard."}, room=request.sid)
    disconnect()

@socketio.on_error_default
def websocket_error_handler(e):
    if isinstance(e, ssl.SSLError) and "HTTP_REQUEST" in str(e):
        return 

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"[ERROR] {str(e)}")
    return "An err # Log the error without stack traceor occurred", 500

#@app.before_request
#def force_https():
#    if request.url.startswith("http://"):
#        return "This server only accepts HTTPS connections.", 403

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

# def kick_dashboard_users():
#     for sid in list(connected_clients):
#         socketio.emit("force_disconnect", {"msg": "Server restarted. Please log in again."}, room=sid)
#         socketio.server.disconnect(sid)
#         connected_clients.remove(sid)

# @app.before_request
# def clear_stale_sessions():
#     if not getattr(app, "_got_first_request", False):
#         try:
#             session.clear()
#             app._got_first_request = True
#             print("[INFO] Cleared stale sessions on server restart.")
#         except Exception as e:
#             print(f"[ERROR] Failed to clear sessions: {e}")

@app.route("/clear_keys_cache", methods=["POST"])
def clear_keys_cache():
    print("[INFO] Forcing client-side key refresh...")
    return jsonify({"success": True, "message": "Client cache refresh triggered."})

@app.before_request
def refresh_session():
    session.modified = True

# ----- Run Flask Server -----
if __name__ == "__main__":
    print("[SUCCESS] Starting server for WSS only...")
    http_server = SecureWSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
