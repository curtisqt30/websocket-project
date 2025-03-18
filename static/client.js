// Get username from sessionStorage
const username = sessionStorage.getItem("username");
const urlParams = new URLSearchParams(window.location.search);
const roomId = urlParams.get('roomId');

// Redirect to login if no username
if (!username) {
    window.location.href = "/login";
} else if (!roomId && !window.location.pathname.includes("/dashboard")) {
    window.location.href = "/dashboard";
}

// Initialize connection
const socket = io("wss://curtisqt.com", {
    path: "/socket.io/",
    transports: ["websocket"]
});

// Authenticate after connecting
socket.on("connect", () => {
    socket.emit("authenticate", { username });
    socket.emit("join", { roomId });
});

socket.on("rate_limit", (data) => alert(data.msg));

socket.on("force_disconnect", (data) => {
    alert(data.msg);
    socket.disconnect();
    window.location.href = "/dashboard";
});

socket.on("room_invalid", (data) => {
    alert(data.msg);
    sessionStorage.removeItem("room");
    window.location.href = "/dashboard";
});

// Handle incoming messages
socket.on("message", (data) => {
    console.log("[DEBUG] Received message:", data);
    appendMessage(data.user, data.msg, false);
});
socket.on("user_joined", (data) => appendMessage(null, data.msg, true));
socket.on("user_left", (data) => appendMessage(null, data.msg, true));

// Handle WebSocket errors
socket.on("error", (error) => {
    console.error("[ERROR] WebSocket error:", error);
    alert("An error occurred with the WebSocket connection.");
});

const maxRooms = 5;

// DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const sendButton = document.getElementById("sendButton");
    const roomList = document.getElementById("roomList");
    const createRoomButton = document.getElementById("createRoom");
    const joinRoomButton = document.getElementById("joinRoom");
    const emojiButton = document.getElementById('emojiButton');
    const emojiPickerContainer = document.getElementById('emoji-picker-container');
    const currentRoom = "{{ roomId }}";
    const messagesContainer = document.getElementById("messages");
    const leaveRoomButton = document.getElementById("leaveRoomButton");

    // Display message for no chatroom
    if (!roomId || roomId === "None") {
        messagesContainer.innerHTML = `
            <p style="color: gray; font-style: italic; text-align: center; margin-top: 20px;">
                You're currently not in a chatroom. Create or join a room using the sidebar.
            </p>`;
        messageInput.disabled = true;
        sendButton.disabled = true;
        emojiButton.disabled = true;
        uploadButton.disabled = true;
    } else {
        messagesContainer.innerHTML = '';
        messageInput.disabled = false;
        sendButton.disabled = false;
        emojiButton.disabled = false;
        uploadButton.disabled = false;
    }

    // Leave room button functionality
    if (leaveRoomButton) {
        leaveRoomButton.addEventListener("click", () => {
            socket.emit("leave", { user: username, roomId: roomId });
            sessionStorage.removeItem("room"); 
            window.location.href = "/dashboard";
        });
    }

    // Display username on the sidebar
    displayUsername(username);

    const maxChars = 150;

    // Load existing rooms
    loadRooms();

    // Character count functionality
    messageInput.addEventListener("input", updateCharCount);
    function updateCharCount() {
        const remaining = maxChars - messageInput.value.length;
        charCount.textContent = `${remaining} characters remaining`;
    }

    // Send message functionality
    sendButton.addEventListener("click", sendMessage);
    messageInput.addEventListener("keypress", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            sendMessage();
        }
    });

    // Room creation functionality
    createRoomButton.addEventListener("click", createRoom);

    // Join room functionality
    joinRoomButton.addEventListener("click", joinRoom);

    // Emoji Picker Setup
    setupEmojiPicker();

    // Hide emoji picker when clicking outside
    document.addEventListener('click', (e) => {
        if (!emojiPickerContainer.contains(e.target) && !emojiButton.contains(e.target)) {
            emojiPickerContainer.style.display = 'none';
        }
    });

    const room = urlParams.get("roomId") || "None";
    document.getElementById("roomId").textContent = room;
    sessionStorage.setItem("room", room);
});

// Function to display username on the sidebar
function displayUsername(username) {
    const usernameDisplay = document.createElement("p");
    usernameDisplay.textContent = `User: ${username}`;
    usernameDisplay.classList.add("username-display");
    document.querySelector(".sidebar").prepend(usernameDisplay);
}

// Function to load existing rooms
function loadRooms() {
    const savedRooms = JSON.parse(sessionStorage.getItem("rooms")) || [];
    savedRooms.forEach(roomId => addRoomToSidebar(roomId));
}

// Function to append messages to chat window
function appendMessage(user, msg, isSystemMessage = false) {
    const messages = document.getElementById("messages");
    const messageElement = document.createElement("div");

    if (isSystemMessage) {
        messageElement.innerHTML = `<p style="font-style: italic;">${msg}</p>`;
    } else {
        const timestamp = new Date().toLocaleTimeString();
        messageElement.innerHTML = `
            <p><strong>[${timestamp}] ${user}:</strong> ${marked.parse(msg)}</p>
        `;
    }
    messages.appendChild(messageElement);
    messages.scrollTop = messages.scrollHeight;
}

// Function to add room to sidebar
function addRoomToSidebar(roomId) {
    const roomItem = document.createElement("div");
    roomItem.classList.add("room-item");

    const roomText = document.createElement("span");
    roomText.textContent = `Room: ${roomId}`;

    const removeButton = document.createElement("button");
    removeButton.textContent = "❌";
    removeButton.classList.add("remove-room-btn");

    removeButton.addEventListener("click", () => {
        removeRoom(roomId);
        roomItem.remove();
    });

    roomItem.appendChild(roomText);
    roomItem.appendChild(removeButton);
    document.getElementById("roomList").appendChild(roomItem);
}

// Function to save room data in sessionStorage
function saveRoom(roomId) {
    const savedRooms = JSON.parse(sessionStorage.getItem("rooms")) || [];
    if (!savedRooms.includes(roomId)) {
        savedRooms.push(roomId);
        sessionStorage.setItem("rooms", JSON.stringify(savedRooms));
    }
}

// Function to remove room from sessionStorage
function removeRoom(roomId) {
    let savedRooms = JSON.parse(sessionStorage.getItem("rooms")) || [];
    savedRooms = savedRooms.filter(room => room !== roomId);
    sessionStorage.setItem("rooms", JSON.stringify(savedRooms));
}

// Function to create a new room
function createRoom() {
    const savedRooms = JSON.parse(sessionStorage.getItem("rooms")) || [];
    if (savedRooms.length >= maxRooms) {
        alert(`You can only have a maximum of ${maxRooms} rooms.`);
        return;
    }

    fetch("/create-room", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            addRoomToSidebar(data.roomId);
            saveRoom(data.roomId);
            window.location.href = `/dashboard?roomId=${data.roomId}`;
        } else {
            alert("Error creating chat: " + data.message);
        }
    });
}

// Function to join an existing room
function joinRoom() {
    const roomId = document.getElementById("roomCode").value.trim().toUpperCase();
    if (roomId.length === 4) {
        addRoomToSidebar(roomId);
        saveRoom(roomId);
        window.location.href = `/dashboard?roomId=${roomId}`;
    } else {
        alert("Enter a valid 4-character room ID.");
    }
}

// Function to setup emoji picker
function setupEmojiPicker() {
    const picker = new EmojiMart.Picker({
        onEmojiSelect: (emoji) => {
            const messageInput = document.getElementById("messageInput");
            messageInput.value += emoji.native;
            updateCharCount();
        },
        theme: 'auto'
    });

    const emojiPickerContainer = document.getElementById('emoji-picker-container');
    emojiPickerContainer.appendChild(picker);

    const emojiButton = document.getElementById('emojiButton');
    emojiButton.addEventListener('click', (event) => {
        event.stopPropagation();  // Prevent immediate close
        emojiPickerContainer.style.display =
            emojiPickerContainer.style.display === 'none' ? 'block' : 'none';
    });
}

let lastMessageTime = 0;

// Function to send a message
function sendMessage() {
    console.log("[DEBUG] sendMessage() triggered");
    const messageInput = document.getElementById("messageInput");
    const message = messageInput.value.trim();

    if (!roomId || roomId === "None") {
        alert("You're not in a room. Please join one first.");
        return;
    }
    if (!message || message.length > 150) {
        alert("Message must be between 1 and 150 characters.");
        return;
    }

    const now = Date.now();
    if (now - lastMessageTime < 1000) {
        alert("You're sending messages too fast! Please wait.");
        return;
    }

    lastMessageTime = now;
    socket.emit("message", { user: username, msg: message, roomId: roomId });
    messageInput.value = "";
    document.getElementById("charCount").textContent = "150 characters remaining";
}