// Get username from sessionStorage
let username = sessionStorage.getItem("username");

// Redirect to login page if no username
if (!username) {
    window.location.href = "/login";
}

// Initialize connection
const socket = io({
    reconnection: false, // Prevent infinite reconnect loop
    transports: ["websocket"]
});

// Authenticate after connecting
socket.on("connect", () => {
    console.log("Connected to WebSocket server.");
    socket.emit("authenticate", { username });
});

// Handle disconnection
socket.on("disconnect", (reason) => {
    console.log("Disconnected from WebSocket:", reason);
});

// User joins the chatroom
socket.on("connect", function () {
    socket.emit("join", { user: username });
});

// Function to append messages to chat window
function appendMessage(user, msg, isSystemMessage) {
    let messages = document.getElementById("messages");

    if (!messages) {
        console.error("Message container not found!");
        return;
    }

    let messageElement = document.createElement("p");

    if (isSystemMessage) {
        messageElement.style.fontStyle = "italic"; // System messages are italic
        messageElement.innerText = msg;
    } else {
        let timestamp = new Date().toLocaleTimeString();
        messageElement.innerText = `[${timestamp}] ${user}: ${msg}`;
    }

    messages.appendChild(messageElement);
}

// Listen for messages from the server
socket.on("message", function (data) {
    appendMessage(data.user, data.msg, false);
});

// Notify when a user joins
socket.on("user_joined", function (data) {
    appendMessage(null, data.msg, true);
});

// DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
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
});

// Function to send a message
function sendMessage() {
    const messageInput = document.getElementById("messageInput");
    const message = messageInput.value.trim();

    if (message.length > 0) {
        socket.emit("message", { user: username, msg: message });
        messageInput.value = "";
        document.getElementById("charCount").textContent = "50 characters remaining";
    }
}
