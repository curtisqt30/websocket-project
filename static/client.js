// username from session storage
let username = sessionStorage.getItem("username");

// Redirect to login page if no username
if (!username) {
    window.location.href = "/";
}

// Establish WebSocket connection with server
let socket = io.connect("ws://" + location.host);

// join event when connected
socket.on("connect", function () {
    console.log("Connected to WebSocket server!");
    socket.emit("join", { user: username });
});

// formatted timestamp
function getTimestamp() {
    let now = new Date();
    return now.toLocaleTimeString();
}

// incoming messages from the server
socket.on("message", function (data) {
    console.log("Received message:", data);
    appendMessage(data.user, data.msg, false);
});

// user join notifications
socket.on("user_joined", function (data) {
    console.log(data.msg);
    appendMessage(null, data.msg, true);
});

// append a message to the chat window
function appendMessage(user, msg, isSystemMessage) {
    let messages = document.getElementById("messages");

    if (!messages) {
        console.error("Message container not found!");
        return;
    }

    let messageElement = document.createElement("p");

    if (isSystemMessage) {
        // Style for system messages
        messageElement.style.fontStyle = "italic";
        messageElement.innerText = msg;
    } else {
        // Format and display user messages with timestamp
        let timestamp = getTimestamp();
        messageElement.innerText = `[${timestamp}] ${user}: ${msg}`;
    }

    messages.appendChild(messageElement);
}

// Wait for DOM to load before adding event listeners
document.addEventListener("DOMContentLoaded", function () {
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const maxChars = 50;

    // Update character count as the user types
    messageInput.addEventListener("input", function () {
        const remaining = maxChars - messageInput.value.length;
        charCount.textContent = `${remaining} characters remaining`;
    });

    // Send message when the "Send" button is clicked
    document.querySelector("button").addEventListener("click", sendMessage);

    // Sned message when Enter-key is pressed to send messages
    messageInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });
});

// Function to send a message
function sendMessage() {
    const messageInput = document.getElementById("messageInput");
    const message = messageInput.value.trim();

    if (message.length > 0) {
        socket.emit("message", { user: username, msg: message }); // Send message to server
        messageInput.value = ""; // Clear input field
        document.getElementById("charCount").textContent = "150 characters remaining"; // Reset character counter
    }
}
