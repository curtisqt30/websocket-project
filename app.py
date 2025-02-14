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

# Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Initialize WebSocket with Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# Load SSL certs
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain("cert.pem", "key.pem")

# User database (stored as JSON)
USER_DB = "users.json"

# Store the last message timestamp for each user (rate-limiting)
user_last_message_time = {}

# ----- Helper Functions -----
def load_users():
    """Load users from JSON file."""
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
    """Save users to JSON file."""
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)

def hash_password(password):
    """Hash passwords using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# ----- Routes -----
@app.route("/")
def home():
    """Redirect to chat if logged in, else go to login."""
    if "username" in session:
        return redirect(url_for("chat_page"))
    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Login endpoint."""
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        users = load_users()

        if username in users and users[username] == password:
            session["username"] = username
            return jsonify({"success": True})

        return jsonify({"success": False, "message": "Invalid credentials"})

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration endpoint."""
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
    """Chat page (requires login)."""
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("chat.html")

@app.route("/logout")
def logout():
    """Log out user."""
    session.pop("username", None)
    return redirect(url_for("login_page"))

# ----- WebSocket Events -----
@socketio.on("connect")
def handle_connect():
    """Handle new WebSocket connections."""
    if "username" not in session:
        print("No session found. Disconnecting WebSocket.")
        disconnect()
        return

    username = session.get("username", "Guest")
    print(f"{username} connected via WebSocket.")
    emit("connected", {"user": username})

@socketio.on("authenticate")
def handle_auth(data):
    """Handle user authentication."""
    username = data.get("username")
    if not username:
        print("No username provided, disconnecting.")
        disconnect()
        return

    print(f"{username} authenticated.")

@socketio.on("join")
def handle_join(data):
    """Handle user joining the chatroom."""
    if "username" not in session:
        return

    username = session.get("username", "Guest")
    join_room("chatroom")
    emit("user_joined", {"msg": f"{username} joined the chat"}, room="chatroom")

@socketio.on("message")
def handle_message(data):
    """Handle incoming chat messages (rate-limited)."""
    global user_last_message_time

    if "username" not in session:
        return

    user = session.get("username", "Guest")
    msg = data.get("msg", "")[:50]  # Limit messages to 50 characters

    now = time.time()

    # Check rate-limit (1 message per second)
    if user in user_last_message_time and now - user_last_message_time[user] < 1:
        emit("rate_limit", {"msg": "You're sending messages too fast! Please wait."}, room=request.sid)
        return

    user_last_message_time[user] = now
    print(f"Received message from {user}: {msg}")
    emit("message", {"user": user, "msg": msg}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    """Handle user disconnection."""
    if "username" in session:
        print(f"{session['username']} disconnected")

@socketio.on("leave")
def handle_leave(data):
    """Handle user leaving the chat."""
    username = data.get("user", "Guest")
    emit("user_left", {"msg": f"{username} has left the chat"}, room="chatroom")
    disconnect()

# ----- Enforce HTTPS & WSS Only -----
@app.before_request
def force_https():
    """Redirect HTTP to HTTPS and block non-secure WebSockets."""
    if request.headers.get("Upgrade", "").lower() == "websocket":
        if request.scheme != "https":
            return "WebSockets must use wss://", 403  # Block ws://
    elif not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), code=301)

# ----- Run Flask Server -----
if __name__ == "__main__":
    print("Starting server with WSS only...")
    http_server = WSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler, certfile="cert.pem", keyfile="key.pem")
    http_server.serve_forever()