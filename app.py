import ssl
import json
import os
import time
import hashlib
from flask import Flask, render_template, redirect, url_for, request, session, jsonify
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

# logging w/ filtering
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("gevent.ssl").setLevel(logging.ERROR)
logging.getLogger("engineio.server").setLevel(logging.CRITICAL)
logging.getLogger("socketio").setLevel(logging.CRITICAL)

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

def log_message(roomId, username, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {username}: {msg}\n"
    log_file = os.path.join(LOGS_FOLDER, f"{roomId}.txt")
    with open(log_file, "a") as file:
        file.write(log_entry)

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
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ROOM={roomId}] {username} joined.")
        emit("user_joined", {"msg": f"{username} joined the chat"}, room=roomId)
    else:
        print(f"[ERROR] Room {roomId} doesn't exist or was deleted.")
        emit("room_invalid", {"msg": f"Room '{roomId}' no longer exists. Redirecting you to the dashboard."}, room=request.sid)

@socketio.on("message")
def handle_message(data):
    # print(f"[DEBUG] Incoming message data: {data}")
    global user_last_message_time
    if "username" not in session:
        return
    user = session.get("username", "Guest")
    msg = data.get("msg", "")[:150]
    roomId = data.get("roomId", "").strip().upper()
    if roomId not in rooms:
        print(f"[ERROR] Room {roomId} doesn't exist.")
        emit("room_invalid", {"msg": f"Room '{roomId}' no longer exists. Redirecting to the dashboard."}, room=request.sid)
        return
    # Rate-limit check
    now = time.time()
    if request.sid in user_last_message_time and now - user_last_message_time[request.sid] < 1:
        emit("rate_limit", {"msg": "You're sending messages too fast! Please wait."}, room=request.sid)
        return
    user_last_message_time[request.sid] = now
    log_message(roomId, user, msg)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ROOM={roomId}] {user}: {msg}")
    emit("message", {"user": user, "msg": msg}, room=roomId)


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

@app.before_request
def clear_stale_sessions():
    if not getattr(app, "_got_first_request", False):
        try:
            session.clear()
            app._got_first_request = True
            print("[INFO] Cleared stale sessions on server restart.")
        except Exception as e:
            print(f"[ERROR] Failed to clear sessions: {e}")

# ----- Run Flask Server -----
if __name__ == "__main__":
    print("Starting server for WSS only...")
    http_server = SecureWSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
