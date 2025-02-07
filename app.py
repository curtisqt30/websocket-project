from flask import Flask, render_template, redirect, url_for
from flask_socketio import SocketIO, emit, join_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Flask init
app = Flask(__name__)

# Secret key for sessions
app.config["SECRET_KEY"] = "secret-key"

jwt = JWTManager(app)

# Initialize flask with CORS allowed for all
socketio = SocketIO(app, cors_allowed_origins="*")

connected_users = {}

### Route definitions ###
@app.route("/")
def home():
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/chat")
def chat_page():
    return render_template("chat.html")

### Websocket Events ### 

@socketio.on("connect")
def handle_connect():
    print("A client connected")

# Print a join notification whenever a user enters a chatroom
@socketio.on("join")
def handle_join(data):
    username = data.get("user")
    join_room("chatroom")
    emit("user_joined", {"msg": f"{username} joined the chat"}, room="chatroom")

@socketio.on("message")
def handle_message(data):
    user = data.get("user")
    msg = data.get("msg")[:50] # limit messages to 50 characters
    print(f"Received message from {user}: {msg}") 
    emit("message", {"user": user, "msg": msg}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    print("A client disconnected")

### Run flask application ###

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)