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
        fetchRoomAESKey(roomId);
    }
    // } else {
    //     console.error("[DEBUG] No roomId found in session storage.");
    // }
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

fetch("/get_private_key", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const formattedKey = data.private_key.trim().replace(/\r?\n|\r/g, '\n');
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
            decryptAESKey(data.encrypted_aes_key); 
        } else {
            console.error("[ERROR] Failed to generate AES key:", data.message);
        }
    });

async function getUserPublicKey() {
    let publicKey = sessionStorage.getItem("public_key");
    
    if (!publicKey) {
        const response = await fetch('/get_public_key');
        const data = await response.json();
        
        if (data.success) {
            publicKey = data.public_key;
            sessionStorage.setItem("public_key", publicKey);
        } else {
            throw new Error("Failed to fetch public key: " + data.message);
        }
    }
    return publicKey;
}

async function decryptAESKey(encryptedKeyBase64) {
    try {
        const privateKeyPEM = sessionStorage.getItem("private_key")
            .replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '');
        const privateKeyDer = Uint8Array.from(atob(privateKeyPEM), c => c.charCodeAt(0));
        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            privateKeyDer.buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );
        const encryptedKey = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
        const decryptedKey = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
        privateKey,
            encryptedKey
        );
        const aesKeyB64 = btoa(String.fromCharCode(...new Uint8Array(decryptedKey)));
        sessionStorage.setItem("aes_key", aesKeyB64);
        return aesKeyB64;
    } catch (error) {
        console.error("[ERROR] decryptAESKey failed:", error);
        return null;
    }
}

async function decryptMessage(encryptedMsgBase64) {
    try {
        const aesKeyBase64 = sessionStorage.getItem("aes_key");
        const aesKey = await crypto.subtle.importKey(
            'raw',
            Uint8Array.from(atob(aesKeyBase64), c => c.charCodeAt(0)),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        const encryptedData = Uint8Array.from(atob(encryptedMsgBase64), c => c.charCodeAt(0));
        const iv = encryptedData.slice(0, 12);
        const ciphertext = encryptedData.slice(12);
        const decryptedArrayBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            ciphertext
        );
        const decryptedText = new TextDecoder().decode(decryptedArrayBuffer);
        return decryptedText;
    } catch (error) {
        console.error("[ERROR] decryptMessage failed:", error);
        return "[ERROR] Unable to decrypt message.";
    }
}

async function encryptMessage(plainText) {
    const aesKeyBase64 = sessionStorage.getItem("aes_key");
    const aesKey = await crypto.subtle.importKey(
        'raw',
        Uint8Array.from(atob(aesKeyBase64), c => c.charCodeAt(0)),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        new TextEncoder().encode(plainText)
    );
    const encryptedArray = new Uint8Array(encryptedContent);
    const combined = new Uint8Array(iv.byteLength + encryptedArray.byteLength);
    combined.set(iv, 0);
    combined.set(encryptedArray, iv.byteLength);
    return btoa(String.fromCharCode(...combined));
}

async function fetchRoomAESKey(roomId) {
    const userPublicKey = await getUserPublicKey();
    const response = await fetch(`/get_room_aes_key/${roomId}`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ user_public_key: userPublicKey })
    });
    const data = await response.json();
    if (data.success) {
        const encryptedAESKey = data.encrypted_room_aes_key;
        const aesKey = await decryptAESKey(encryptedAESKey); 
        sessionStorage.setItem(`room_aes_key_${roomId}`, aesKey);
        console.log(`AES key stored for room ${roomId}`);
    } else {
        console.error("Failed to fetch AES key:", data.message);
    }
}

async function encryptRoomMessage(roomId, plainText) {
    const aesKeyBase64 = sessionStorage.getItem(`room_aes_key_${roomId}`);
    const aesKey = await crypto.subtle.importKey(
        'raw',
        Uint8Array.from(atob(aesKeyBase64), c => c.charCodeAt(0)),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        new TextEncoder().encode(plainText)
    );
    const encryptedArray = new Uint8Array(encryptedContent);
    const combined = new Uint8Array(iv.byteLength + encryptedArray.byteLength);
    combined.set(iv, 0);
    combined.set(encryptedArray, iv.byteLength);
    return btoa(String.fromCharCode(...combined));
}

async function decryptRoomMessage(roomId, encryptedMsgBase64) {
    const aesKeyBase64 = sessionStorage.getItem(`room_aes_key_${roomId}`);
    if (!aesKeyBase64) {
        console.error("AES key not found for this room.");
        return "[ERROR] Key missing.";
    }
    const aesKey = await crypto.subtle.importKey(
        'raw',
        Uint8Array.from(atob(aesKeyBase64), c => c.charCodeAt(0)),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    const encryptedData = Uint8Array.from(atob(encryptedMsgBase64), c => c.charCodeAt(0));
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    try {
        const decryptedArrayBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            ciphertext
        );
        return new TextDecoder().decode(decryptedArrayBuffer);
    } catch (error) {
        console.error("[ERROR] decryptMessage failed:", error);
        return "[ERROR] Unable to decrypt message.";
    }
}

// Handle incoming messages
socket.on("message", async (data) => {
    const decryptedMsg = await decryptRoomMessage(roomId, data.msg);
    try {
        const msgObject = JSON.parse(decryptedMsg);
        if (msgObject.type === 'file') {
            appendFileMessage(data.user, msgObject);
        } else {
            appendMessage(data.user, decryptedMsg, false);
        }
    } catch (error) {
        appendMessage(data.user, decryptedMsg, false);
    }
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
        const remaining = maxChars - [...messageInput.value].length; 
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
        fileInput.addEventListener("change", async (event) => {
            const file = event.target.files[0];
            if (!file) return;
            if (file.size > 8 * 1024 * 1024) {
                alert("File size exceeds 8MB.");
                return;
            }
            const formData = new FormData();
            formData.append("file", file);
            try {
                const response = await fetch("/upload", {
                    method: "POST",
                    body: formData,
                });
                const data = await response.json();
                if (data.success) {
                    const fileMessage = JSON.stringify({
                        type: 'file',
                        filename: data.filename,
                        url: `/uploads/${data.filename}`
                    });
                    const encryptedFileMsg = await encryptMessage(fileMessage);
                    socket.emit("message", { user: username, msg: encryptedFileMsg, roomId });
                } else {
                    alert(data.message);
                }
            } catch (error) {
                console.error("[ERROR] Upload failed:", error);
            }
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
        let cleanMsg = msg;
        if (!msg || msg.startsWith("[ERROR]")) {
            cleanMsg = "<em>[Could not decrypt this message]</em>";
        } else {
            cleanMsg = marked.parse(msg).replace(/<p>|<\/p>/g, '');
        }
        messageElement.innerHTML = `<div>
            <strong>[${timestamp}] ${user}:</strong> 
            <span>${cleanMsg}</span>
        </div>`;
    }
    messages.appendChild(messageElement);
    messages.scrollTop = messages.scrollHeight;
}

function appendFileMessage(user, msgObject) {
    const messages = document.getElementById("messages");
    const messageElement = document.createElement("div");
    const timestamp = new Date().toLocaleTimeString();
    let fileContent;
    if (/\.(jpg|jpeg|png|gif)$/i.test(msgObject.filename)) {
        fileContent = `<img src="${msgObject.url}" alt="${msgObject.filename}" style="max-width:300px; border:1px solid #ccc;">`;
    } else if (/\.pdf$/i.test(msgObject.filename)) {
        fileContent = `<a href="${msgObject.url}" target="_blank">📄 ${msgObject.filename}</a>`;
    } else {
        fileContent = `<a href="${msgObject.url}" target="_blank">${msgObject.filename}</a>`;
    }
    messageElement.innerHTML = `<div>
        <strong>[${timestamp}] ${user}:</strong>
        <span>${fileContent}</span>
    </div>`;
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
        event.stopPropagation();
        emojiPickerContainer.style.display =
            emojiPickerContainer.style.display === 'none' ? 'block' : 'none';
    });
}

// Ensure keys are fetched and stored securely
fetch("/get_private_key", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const formattedKey = data.private_key.trim().replace(/\r?\n|\r/g, '\n');
            sessionStorage.setItem("private_key", formattedKey);
        } else {
            console.error("[ERROR] Failed to retrieve private key:", data.message);
        }
    })
    .catch(error => console.error("[ERROR] Failed to fetch private key:", error));

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
                }
            });
    }
});

let lastMessageTime = 0;

// Function to send a message
async function sendMessage() {
    const messageInputElement = document.getElementById("messageInput");
    const message = messageInputElement.value.trim();
    if (!roomId || roomId === "None") {
        alert("You're not in a room. Please join one first.");
        return;
    }
    if (!message || message.length > 150) {
        alert("Message must be between 1 and 150 characters.");
        return;
    }
    const encryptedMsg = await encryptMessage(message);
    socket.emit("message", { user: username, msg: encryptedMsg, roomId });
    messageInputElement.value = "";
    document.getElementById("charCount").textContent = "150 characters remaining";
}
