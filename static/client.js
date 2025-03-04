// Get username from sessionStorage
let username = sessionStorage.getItem("username");
let room = new URLSearchParams(window.location.search).get("room");

// Redirect to login page if no username
if (!username) {
    window.location.href = "/login";
}

// Initialize connection
const protocol = window.location.protocol === "https:" ? "wss" : "ws";
const socket = io("wss://localhost:5000", {
    transports: ["websocket"]
});

// Authenticate after connecting
socket.on("connect", () => {
    console.log("Connected as ${username}");
    socket.emit("authenticate", { username });
    if (room) {
        socket.emit("join", { room: room });
        document.getElementById("roomId").innerText = room;
    }
});

// Handle disconnection
socket.on("disconnect", (reason) => {
    console.log("Disconnected from WebSocket:", reason);
});

// Alert message rate limit
socket.on("rate_limit", function (data) {
    alert(data.msg);
});

// System message notify that User joins the chatroom
socket.on("connect", function () {
    const roomId = sessionStorage.getItem("room");
    socket.emit("join", { user: username, room: roomId });
});

// // Handle inactivity warning
// socket.on("inactivity_warning", function (data) {
//     alert(data.msg);
// });     alert(data.msg);
// });


// Handle forced disconnection
socket.on("force_disconnect", function (data) {
    alert(data.msg);
    socket.disconnect();
    window.location.href = "/logout";
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
}

// Handle incoming messages
socket.on("message", (data) => {
    appendMessage(data.user, data.msg);
});

// System message notify when a user joins
socket.on("user_joined", function (data) {
    appendMessage(null, data.msg, true);
});

// DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const leaveChatButton = document.getElementById("leaveChat");
    const maxChars = 50;

    // Update character count as the user types
    messageInput.addEventListener("input", function () {
        const remaining = maxChars - messageInput.value.length;
        charCount.textContent = `${remaining} characters remaining`;
    });

    // Send message when "Send" button is clicked
    document.getElementById("sendButton").addEventListener("click", sendMessage);

    // Send message when Enter key is pressed
    messageInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            sendMessage();
        }
    });
    // Leave chat button event
    leaveChatButton.addEventListener("click", function () {
        socket.emit("leave", { room: room, user: username });
        sessionStorage.removeItem("username");
        window.location.href = "/logout";
    });
});

// Send a message with a 1 second cooldown.
let lastMessageTime = 0;

function sendMessage() {
    const messageInput = document.getElementById("messageInput");
    let message = messageInput.value.trim();

    if (message.length === 0) return;
    if (message.length > 50) {
        alert("Message cannot exceed 50 characters!");
        return;
    }

    let now = Date.now();
    if (now - lastMessageTime < 1000) {
        alert("You're sending messages too fast! Please wait.");
        return;
    }

    lastMessageTime = now;

    const urlParams = new URLSearchParams(window.location.search);
    const roomId = urlParams.get("room") || "Unknown";

    socket.emit("message", { user: username, msg: message, room: roomId });
    messageInput.value = "";
    document.getElementById("charCount").textContent = "50 characters remaining";
}
