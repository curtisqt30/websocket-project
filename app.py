from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"

@socketio.on("connect")
def handle_connect():
    pass

@socketio.on("join")
def handle_join(data):
    pass

@socketio.on("message")
def handle_message(data):
    pass

@socketio.on("disconnect")
def handle_disconnect():
    pass

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
