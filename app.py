from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
socketio = SocketIO(app)

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/chat")
def chat_page():
    return render_template("chat.html")

@socketio.on("connect")
def handle_connect():
    print("A client connected")
    
@socketio.on("join")
def handle_join(data):
    username = data.get("user")
    join_room("chatroom")
    emit("user_joined", {"msg": f"{username} joined the chat"}, room="chatroom")

@socketio.on("message")
def handle_message(data):
    user = data.get("user")
    msg = data.get("msg")
    print(f"Received message from {user}: {msg}")
    emit("message", {"user": user, "msg": msg}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    print("A client disconnected")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
