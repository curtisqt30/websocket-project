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

# Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# logging w/ filtering
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("gevent.ssl").setLevel(logging.ERROR)
logging.getLogger("engineio.server").setLevel(logging.CRITICAL)
logging.getLogger("socketio").setLevel(logging.CRITICAL)

# Initialize WebSocket with Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

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

# ----- Helper Functions -----

# Active rooms
rooms = {}

def generate_room():
    # generate 4 character room id
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
    return hashlib.sha256(password.encode()).hexdigest()

def monitor_inactivity():
    while True:
        now = time.time()
        for sid, last_msg_time in list(user_last_message_time.items()):
            if now - last_msg_time > 120: 
                socketio.emit("force_disconnect", {"msg": "You have been disconnected due to inactivity."}, room=sid)
                socketio.server.disconnect(sid)
                del user_last_message_time[sid]
        time.sleep(5)

Thread(target=monitor_inactivity, daemon=True).start()
user_last_message_time = {}

# ----- Routes -----
@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return redirect(url_for("rooms_page"))

@app.route("/rooms")
def rooms_page():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("rooms.html")

# create a new room and reuturn the room id
@app.route("/create-room", methods=["POST"])
def create_room():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room_code = generate_room()
    # make sure that there are no duplicate room ids
    while room_code in rooms:
        room_code = generate_room()
    rooms[room_code] = {"users": []}
    return jsonify({"success": True, "room": room_code})

@app.route("/join-room")
def join_room_route():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room_code = request.args.get("room")
    if not room_code or room_code not in rooms:
        return redirect(url_for("rooms_page"))
    return redirect(f"/chat?room={room_code}")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        users = load_users()
        if username in users and users[username] == password:
            session["username"] = username
            print(f"[LOGIN] {username} successfully logged in.")
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Invalid credentials"})
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users:
            return render_template("register.html", error="Username already taken")
        users[username] = hash_password(password)
        save_users(users)
        return redirect(url_for("login_page"))
    return render_template("register.html")

@app.route("/chat")
def chat_page():
    if "username" not in session:
        return redirect(url_for("login_page"))
    room = request.args.get("room", "")
    if not room or room not in rooms:
        return redirect(url_for("rooms_page"))
    return render_template("chat.html", room=room)

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login_page"))

# ----- WebSocket Events -----
@socketio.on("connect")
def handle_connect():
    if request.environ.get("wsgi.url_scheme", "") == "ws":
        print("[SECURITY] Blocked invalid ws:// connection attempt before SSL handshake.")
        disconnect()
        return
    if "username" not in session:
        print("No session found. Disconnecting.")
        disconnect()
        return
    user_last_message_time[request.sid] = time.time()
    username = session.get("username", "Guest")
    print(f"[USER CONNECT] {username} connected & authenticated.")
    emit("connected", {"user": username})

@socketio.on("authenticate")
def handle_auth(data):
    username = data.get("username")
    if not username:
        print("No username provided, disconnecting.")
        disconnect()
        return

@socketio.on("join")
def handle_join(data):
    if "username" not in session:
        return
    username = session["username"]
    room_code = data.get("room", "").strip().upper()
    if room_code not in rooms:
        print(f"[ERROR] Room {room_code} doesn't exist.")
        return
    join_room(room_code)
    rooms[room_code]["users"].append(username)
    print(f"[ROOM={room_code}] {username} joined.")
    emit("user_joined", {"msg": f"{username} joined the chat", "room": room_code}, room=room_code)

# Limit messages to 50 characters
# Check rate-limit (1 message per second)
@socketio.on("message")
def handle_message(data):
    global user_last_message_time
    if "username" not in session:
        return
    user = session.get("username", "Guest")
    msg = data.get("msg", "")[:50] # Limit messages to 50 characters
    room_code = data.get("room", "").strip().upper()
    if room_code not in rooms:
        print(f"[ERROR] Room {room_code} doesn't exist.")
        return
    now = time.time()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Check rate-limit (1 message per second)
    if request.sid in user_last_message_time and now - user_last_message_time[request.sid] < 1:
        emit("rate_limit", {"msg": "You're sending messages too fast Please wait."}, room=request.sid)
        return
    user_last_message_time[request.sid] = now
    print(f"[ROOM={room_code}, {timestamp}] {user}: {msg}")
    emit("message", {"user": user, "msg": msg, "room": room_code}, room=room_code)

@socketio.on("disconnect")
def handle_disconnect():
    if "username" in session:
        print(f"{session['username']} disconnected")

@socketio.on("leave")
def handle_leave(data):
    username = data.get("user", "Guest")
    emit("user_left", {"msg": f"{username} has left the chat"}, room="chatroom")
    disconnect()

@socketio.on_error_default
def websocket_error_handler(e):
    if isinstance(e, ssl.SSLError) and "HTTP_REQUEST" in str(e):
        return 

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"[ERROR] {str(e)}")
    return "An err # Log the error without stack traceor occurred", 500

@app.before_request
def force_https():
    if request.url.startswith("http://"):
        return "This server only accepts HTTPS connections.", 403  # Forbidden

# Custom Gevent WSGIServer
class SecureWSGIServer(WSGIServer):
    def wrap_socket_and_handle(self, client_socket, address):
        global last_ssl_error_time
        try:
            peek = client_socket.recv(5, socket.MSG_PEEK) 
            if peek.startswith(b"GET /") or peek.startswith(b"POST "):
                now = time.time()
                if now - last_ssl_error_time > 1: 
                    print("[SECURITY] Dropped invalid HTTP request on HTTPS socket.")
                    last_ssl_error_time = now
                client_socket.close()
                return
            
            super().wrap_socket_and_handle(client_socket, address)
        except Exception as e:
            now = time.time()
            if now - last_ssl_error_time > 1: 
                print(f"[SECURITY] SSL Error: {e}")
                last_ssl_error_time = now
            client_socket.close()

# ----- Run Flask Server -----
if __name__ == "__main__":
    print("Starting server for WSS only...")
    http_server = SecureWSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler, certfile="cert.pem", keyfile="key.pem")
    http_server.serve_forever()
