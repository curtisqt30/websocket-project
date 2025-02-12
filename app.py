from flask import Flask, render_template, redirect, url_for, request, session, jsonify, copy_current_request_context
from flask_socketio import SocketIO, emit, join_room, disconnect
import json
import os
import hashlib

# Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SESSION_TYPE"] = "null"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_FILE_DIR"] = "./flask_session"

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# User database
USER_DB = "users.json"

# Load users from database
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

# Save users to database
def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)

# Hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Route for home 
@app.route("/")
def home():
    print(f"Session contents: {session}")  # Debugging
    if "username" in session:
        return redirect(url_for("chat_page"))
    return redirect(url_for("login_page"))

# Login page
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        users = load_users()

        if username in users and users[username] == password:
            session["username"] = username  
            return jsonify({"success": True})
        
        return jsonify({"success": False, "message": "Invalid credentials"})

    return render_template("login.html")


# Registration page
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

# Chat page 
@app.route("/chat")
def chat_page():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("chat.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("username", None) 
    return redirect(url_for("login_page")) 

# Websocket Events
@socketio.on("connect")
def handle_connect():
    if "username" not in session:
        print("No session found. Disconnecting.")
        disconnect()
        return
    
    username = session.get("username", "Guest")
    print(f"{username} connected.")

    emit("connected", {"user": username})

@socketio.on("authenticate")
def handle_auth(data):
    username = data.get("username")
    if not username:
        print("No username provided, disconnecting.")
        disconnect()
        return
    
    print(f"{username} authenticated.")

@socketio.on("join")
def handle_join(data):
    if "username" not in session:
        return
    username = session.get("username", "Guest")
    join_room("chatroom")
    emit("user_joined", {"msg": f"{username} joined the chat"}, room="chatroom")

@socketio.on("message")
def handle_message(data):
    if "username" not in session:
        return
    user = session.get("username", "Guest")
    msg = data.get("msg")[:50]  # Limit messages to 50 characters
    print(f"Received message from {user}: {msg}")
    emit("message", {"user": user, "msg": msg}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    if "username" in session:
        print(f"{session['username']} disconnected")

@app.route("/debug-session")
def debug_session():
    return jsonify(dict(session))

# Run Flask application
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
