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
    transports: ["websocket"],
    timeout: 40000,            
    reconnectionAttempts: 20,  
    reconnectionDelay: 2000    
});

console.log("[DEBUG] Attempting WebSocket Connection...");

socket.on("connect", () => {
    console.log("[DEBUG] Socket.IO Connected Successfully");

    if (username) {
        console.log(`[DEBUG] Attempting Authentication with username: ${username}`);
        socket.emit("authenticate", { username });
    } else {
        console.error("[DEBUG] No username found in session storage.");
    }

    if (roomId) {
        console.log(`[DEBUG] Attempting to Join Room: ${roomId}`);
        socket.emit("join", { roomId });
    }
    // } else {
    //     console.error("[DEBUG] No roomId found in session storage.");
    // }
});

// Forge library check
if (typeof forge === "undefined") {
    console.error("[ERROR] Forge library is not loaded.");
} else {
    console.log("[DEBUG] Forge library loaded successfully.");
}

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

fetch("/get_private_key", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log("[DEBUG] Private Key Received:", data.private_key);
            const formattedKey = data.private_key.trim().replace(/\r?\n|\r/g, '\n'); // 🔹 Fix formatting
            sessionStorage.setItem("private_key", formattedKey);
        } else {
            console.error("[ERROR] Failed to retrieve private key:", data.message);
        }
    })
    .catch(error => console.error("[ERROR] Failed to fetch private key:", error));

fetch("/generate_aes_key", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log("[DEBUG] Encrypted AES Key Received:", data.encrypted_aes_key);
            const aesKey = decryptAESKey(data.encrypted_aes_key); 
            if (!aesKey) {
                console.error("[ERROR] Decrypted AES key is null.");
            } else {
                console.log("[DEBUG] AES Key decrypted successfully.");
                sessionStorage.setItem("aes_key", aesKey); 
            }
        }
    });

function decryptAESKey(encryptedKey) {
    console.log("[DEBUG] Decrypting AES Key:", encryptedKey);
    try {
        const privateKeyPEM = sessionStorage.getItem("private_key");
        if (!privateKeyPEM) {
            throw new Error("Private key not found in sessionStorage.");
        }
        const formattedKey = privateKeyPEM.trim().replace(/\r?\n|\r/g, '\n');
        const privateKey = forge.pki.privateKeyFromPem(formattedKey);
        const decodedKey = forge.util.decode64(encryptedKey.trim());
        console.log("[DEBUG] Decoded AES Key Length Before Decryption:", decodedKey.length);
        const decryptedKey = privateKey.decrypt(decodedKey, 'RSA-OAEP', {
            md: forge.md.sha256.create()
        });
        console.log("[DEBUG] Decrypted AES Key Length After Decryption:", decryptedKey.length);
        if (!decryptedKey || decryptedKey.length !== 32) {
            console.error("[ERROR] AES Key size mismatch. Expected 32 bytes.");
            return null;
        }
        const aesKeyB64 = forge.util.encode64(decryptedKey);  
        sessionStorage.setItem("aes_key", aesKeyB64);
        console.log("[DEBUG] AES Key decrypted successfully.");
        return aesKeyB64;
    } catch (error) {
        console.error("[ERROR] Failed to decrypt AES key:", error.message);
        return null;
    }
}
    
function decryptMessage(encryptedMsg) {
    const aesKeyBase64 = sessionStorage.getItem("aes_key");
    if (!aesKeyBase64) {
        console.error("[ERROR] AES key not found in sessionStorage.");
        return "[ERROR] Failed to decrypt message.";
    }
    const aesKey = new Uint8Array(JSON.parse(aesKeyBase64));
    if (aesKey.length !== 32) {
        console.error("[ERROR] AES Key size mismatch. Expected 32 bytes.");
        return "[ERROR] AES Key size invalid.";
    }
    try {
        const binaryData = encryptedMsg;
        if (binaryData.length < 16) {
            console.error("[ERROR] Encrypted data is too short for IV + Ciphertext.");
            return "[ERROR] Invalid encrypted message format.";
        }
        const iv = binaryData.slice(0, 16);
        const ciphertext = binaryData.slice(16);
        const decryptedBytes = CryptoJS.AES.decrypt(
            { ciphertext: CryptoJS.lib.WordArray.create(ciphertext) },
            CryptoJS.lib.WordArray.create(aesKey),
            {
                iv: CryptoJS.lib.WordArray.create(iv),
                mode: CryptoJS.mode.CFB,
                padding: CryptoJS.pad.NoPadding
            }
        );
        const decryptedMsg = decryptedBytes.toString(CryptoJS.enc.Utf8);
        if (!decryptedMsg || decryptedMsg.trim() === "") {
            throw new Error("Decrypted message is empty or corrupted.");
        }
        return decodeURIComponent(decryptedMsg);
    } catch (error) {
        console.error("[ERROR] Decryption failed:", error.message || error);
        return "[ERROR] Failed to decrypt message.";
    }
}


// Handle incoming messages
socket.on("message", (data) => {
    const encryptedMsg = new Uint8Array(data.msg);
    const decryptedMsg = decryptMessage(encryptedMsg);
    appendMessage(data.user, decryptedMsg, false);
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
    // const roomList = document.getElementById("roomList");
    const createRoomButton = document.getElementById("createRoom");
    const joinRoomButton = document.getElementById("joinRoom");
    const emojiButton = document.getElementById('emojiButton');
    const emojiPickerContainer = document.getElementById('emoji-picker-container');
    // const currentRoom = "{{ roomId }}";
    const messagesContainer = document.getElementById("messages");
    const leaveRoomButton = document.getElementById("leaveRoomButton");
    const uploadButton = document.getElementById("uploadButton");

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

    // Upload file functionality
    uploadButton.addEventListener("click", () => {
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.addEventListener("change", (event) => {
            const file = event.target.files[0];
            if (!file) return;
            // Early size check (8MB limit)
            if (file.size > 8 * 1024 * 1024) {
                alert("File size exceeds the 8MB limit. Please upload a smaller file.");
                return;
            }
            const formData = new FormData();
            formData.append("file", file);
            fetch("/upload", {
                method: "POST",
                body: formData,
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const fileLink = `<a href="/uploads/${data.filename}" target="_blank">${data.filename}</a>`;
                    socket.emit("message", { user: username, msg: fileLink, roomId: roomId });
                } else {
                    alert(data.message);
                }
            })
            .catch((error) => console.error("[ERROR] Upload failed:", error));
        });
        fileInput.click();
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
    const timestamp = new Date().toLocaleTimeString();
    if (isSystemMessage) {
        messageElement.innerHTML = `<div style="font-style: italic;">${msg}</div>`;
    } else {
        const cleanMsg = marked.parse(msg).replace(/<p>|<\/p>/g, '');
        messageElement.innerHTML = `<div>
            <strong>[${timestamp}] ${user}:</strong> 
            <span>${cleanMsg}</span>
        </div>`;
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

// Ensure keys are fetched and stored securely
function fetchPrivateKey() {
    fetch("/get_private_key", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log("[DEBUG] Private Key Received:", data.private_key);
            const formattedKey = data.private_key.trim().replace(/\r?\n|\r/g, '\n');
            
            if (!formattedKey.includes("-----BEGIN PRIVATE KEY-----") || 
                !formattedKey.includes("-----END PRIVATE KEY-----")) {
                console.error("[ERROR] Private key format is invalid or incomplete.");
                return;
            }

            sessionStorage.setItem("private_key", formattedKey);
        } else {
            console.error("[ERROR] Failed to retrieve private key:", data.message);
        }
    })
    .catch(error => console.error("[ERROR] Failed to fetch private key:", error));
}

// Clear stale keys on refresh
window.addEventListener("load", () => {
    if (!sessionStorage.getItem("private_key")) {
        console.log("[DEBUG] Private key not found, fetching again...");
        fetchPrivateKey();
    }
    if (!sessionStorage.getItem("aes_key")) {
        console.log("[DEBUG] AES key not found, requesting again...");
        fetch("/generate_aes_key", { method: "POST" })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    decryptAESKey(data.encrypted_aes_key);
                } else {
                    console.error("[ERROR] Failed to fetch AES key.");
                }
            });
    }
});

let lastMessageTime = 0;

// Function to send a message
function sendMessage() {
    console.log("[DEBUG] sendMessage() triggered");
    const messageInputElement = document.getElementById("messageInput");
    const message = messageInputElement.value.trim();
    if (!roomId || roomId === "None") {
        console.warn("[DEBUG] No roomId found. Aborting message.");
        alert("You're not in a room. Please join one first.");
        return;
    }

    if (!message || message.length > 150) {
        console.warn("[DEBUG] Invalid message length. Aborting.");
        alert("Message must be between 1 and 150 characters.");
        return;
    }
    const encoder = new TextEncoder();
    const messageBuffer = encoder.encode(messageInput);
    console.log(`[DEBUG] Sending Message: "${messageInput}" as Buffer`);
    socket.emit("message", { user: username, msg: messageBuffer, roomId: roomId });
    document.getElementById("messageInput").value = "";
    document.getElementById("charCount").textContent = "150 characters remaining";
}