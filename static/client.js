// Get username from sessionStorage
let username = sessionStorage.getItem("username");
let urlParams = new URLSearchParams(window.location.search);
let room = urlParams.get('room');

// Redirect to login page if no username
if (!username || !room) {
    window.location.href = "/rooms";
}

// Initialize connection
const socket = io("wss://localhost:5000", {
    transports: ["websocket"]
});

// Authenticate after connecting
socket.on("connect", () => {
    socket.emit("authenticate", { username });
    socket.emit("join", { room });
});

// Handle disconnection
socket.on("disconnect", (reason) => {
    console.log("Disconnected from WebSocket:", reason);
});

// Alert message rate limit
socket.on("rate_limit", function (data) {
    alert(data.msg);
});

// Handle forced disconnection
socket.on("force_disconnect", function (data) {
    alert(data.msg);
    socket.disconnect();
    window.location.href = "/rooms";
});

// Function to append messages to chat window
function appendMessage(user, msg, isSystemMessage = false) {
    let messages = document.getElementById("messages");
    let messageElement = document.createElement("p");

    if (isSystemMessage) {
        messageElement.style.fontStyle = "italic";
        messageElement.innerText = msg;
    } else {
        let timestamp = new Date().toLocaleTimeString();
        messageElement.innerText = `[${timestamp}] ${user}: ${msg}`;
    }

    messages.appendChild(messageElement);
    messages.scrollTop = messages.scrollHeight;
}

// Handle incoming messages
socket.on("message", function (data) {
    appendMessage(data.user, data.msg, false);
});

// System message notify when a user joins
socket.on("user_joined", function (data) {
    appendMessage(null, data.msg, true);
});

// System message notify when a user leaves
socket.on("user_left", function (data) {
    appendMessage(null, data.msg, true);
});

// DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("roomId").textContent = room;
    
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const sendButton = document.getElementById("sendButton");
    const leaveChatButton = document.getElementById("leaveChat");
    const maxChars = 50;

    messageInput.addEventListener("input", function () {
        const remaining = maxChars - messageInput.value.length;
        charCount.textContent = `${remaining} characters remaining`;
    });

    sendButton.addEventListener("click", sendMessage);
    messageInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            sendMessage();
        }
    });
    leaveChatButton.addEventListener("click", function () {
        socket.emit("leave", { user: username, room });
        window.location.href = "/rooms";
    });
});

// Send a message with a 1 second cooldown.
let lastMessageTime = 0;

function sendMessage() {
    const messageInput = document.getElementById("messageInput");
    let message = messageInput.value.trim();
    const room = urlParams.get("room");

    if (message.length === 0 || message.length > 50) {
        alert("Message must be between 1 and 50 characters.");
        return;
    }

    let now = Date.now();
    if (now - lastMessageTime < 1000) {
        alert("You're sending messages too fast! Please wait.");
        return;
    }

    lastMessageTime = now;
    socket.emit("message", { user: username, msg: message, room: room });
    messageInput.value = "";
    document.getElementById("charCount").textContent = "50 characters remaining";
}
