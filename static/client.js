// Get username from sessionStorage
const username = sessionStorage.getItem("username");
const urlParams = new URLSearchParams(window.location.search);
const roomId = urlParams.get('roomId');

if (!roomId || roomId === "None") {
    sessionStorage.removeItem("room");
} else {
    sessionStorage.setItem("room", roomId);
}

// Redirect to login if no username
if (!username) {
    window.location.href = "/login";
} else if (!roomId && !window.location.pathname.includes("/dashboard")) {
    window.location.href = "/dashboard";
}

// Initialize connection
const socket = io(window.location.origin, {
    path: "/socket.io",
    transports: ["websocket"]
});

setInterval(() => {
    socket.emit("heartbeat", { user: username });
}, 30000);  // every 30 seconds

const typingUsers = new Set();
function renderTypingBanner(){
    const banner = document.getElementById("typingBanner");
    if (typingUsers.size === 0){
        banner.style.display = "none";
        return;
    }
    banner.style.display = "block";
    const names = [...typingUsers];
    const text =
        names.length === 1 ? `${names[0]} is typing…` :
        names.length === 2 ? `${names[0]} and ${names[1]} are typing…` :
        `${names.slice(0,-1).join(", ")} and ${names.slice(-1)} are typing…`;
    banner.textContent = text;
}

async function fetchRoomAESKey(roomId) {
    try {
        const userPublicKey = await getUserPublicKey();
        if (!userPublicKey) {
            console.error("[ERROR] User public key missing");
            return;
        }
        const response = await fetch(`/get_room_aes_key/${roomId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_public_key: userPublicKey })
        });
        const data = await response.json();
        if (!data.success) {
            console.error("[ERROR] Failed to fetch room AES key:", data.message);
            return;
        }
        const privateKeyPEM = sessionStorage.getItem("private_key");
        if (!privateKeyPEM) {
            console.error("[ERROR] Private key not found in sessionStorage");
            return;
        }
        const keyPemClean = privateKeyPEM
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(/\s+/g, '');
        const binaryDer = str2ab(atob(keyPemClean));
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );
        const encryptedKeyBytes = Uint8Array.from(atob(data.encrypted_room_aes_key), c => c.charCodeAt(0));
        const decryptedKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedKeyBytes
        );
        const b64Key = btoa(String.fromCharCode(...new Uint8Array(decryptedKey)));
        sessionStorage.setItem(`room_aes_key_${roomId}`, b64Key);
        console.log(`[INFO] AES key successfully stored for room ${roomId}`);
    } catch (err) {
        console.error("[ERROR] fetchRoomAESKey failed:", err);
    }
}

socket.on("connect", () => {
    console.log("Socket.IO Connected Successfully");
    if (username) {
        socket.emit("authenticate", { username });
        updateChatPanelVisibility(
            document.querySelector(".welcome-panel"),
            document.querySelector(".chat-pane")
        );
        if (roomId && roomId !== "None") {
            console.log(`Attempting to Join Room: ${roomId}`);
            socket.emit("join", { roomId });
            fetchRoomAESKey(roomId);
        }
    }
});

function updateChatPanelVisibility(welcomePanel, chatPane) {
    const roomIdParam = urlParams.get('roomId');
    if (!roomIdParam || roomIdParam === "None") {
        if (welcomePanel) welcomePanel.style.display = "block";
        if (chatPane) chatPane.style.display = "none";
        document.getElementById("rosterList").innerHTML = "";
    } else {
        if (welcomePanel) welcomePanel.style.display = "none";
        if (chatPane) chatPane.style.display = "block";
    }
}

socket.on("user_joined", (data) => {
    console.log(data.msg);
    if (roomId && roomId !== "None") { 
        fetchRoomAESKey(roomId);
    }
    sessionStorage.setItem("room", roomId);
    updateChatPanelVisibility(
        document.querySelector(".welcome-panel"),
        document.querySelector(".chat-pane")
    );
    appendMessage(null, data.msg, true);
});

socket.on("rate_limit", (data) => alert(data.msg));

socket.on("roster_update", (data) => {
const rosterEl = document.getElementById("rosterList");
    if (!rosterEl) { return; }
    rosterEl.innerHTML = "";
    if (!data.users || data.users.length === 0) {
        rosterEl.innerHTML = "<p>No users in room.</p>";
        return;
    }
    rosterEl.innerHTML = "";
    rosterEl.innerHTML = data.users.map(userObj => {
        const statusClass = userObj.state === "online" ? "status-online" :
                            userObj.state === "idle" ? "status-idle" : "status-offline";
        return `<div class="roster-row">
                    <span class="status-dot ${statusClass}"></span> ${userObj.user}
                </div>`;
    }).join('');
});

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

socket.on("presence_update", stateList => {
    const rosterList = document.getElementById("rosterList");
    rosterList.innerHTML = stateList.map(u => {
        const color = u.state === "online" ? "green" : "gray";
        return `<p style="color:${color}">${u.user} (${u.state})</p>`;
    }).join("");
});

// receive updates
socket.on("typing", ({user, typing}) => {
    if (typing) {
        typingUsers.add(user);
    } else {
        typingUsers.delete(user);
    }
    renderTypingBanner();
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
        const privateKeyPEM = sessionStorage.getItem("private_key");
        if (!privateKeyPEM) throw new Error("Private key not found");
        const keyPem = privateKeyPEM
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(/\s/g, '');
        const binaryDer = str2ab(atob(keyPem));
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );
        const encryptedKeyBytes = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
        const decryptedKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedKeyBytes
        );
        const b64Key = btoa(String.fromCharCode(...new Uint8Array(decryptedKey)));
        const rawKeyBytes = Uint8Array.from(atob(b64Key), c => c.charCodeAt(0));
        if (rawKeyBytes.length !== 16 && rawKeyBytes.length !== 32) {
            console.error("[ERROR] Invalid AES Key size. Expected 16 or 32 bytes.");
            return;
        }
        
        sessionStorage.setItem(`room_aes_key_${roomId}`, b64Key);
        return b64Key;
    } catch (error) {
        console.error("[ERROR] decryptAESKey failed:", error);
        return null;
    }
}

async function decryptMessage(encryptedMsgBase64) {
    try {
        const aesKeyBase64 = sessionStorage.getItem(`room_aes_key_${roomId}`);
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

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

async function encryptRoomMessage(roomId, plainText) {
    const aesKeyBase64 = sessionStorage.getItem(`room_aes_key_${roomId}`);
    if (!aesKeyBase64) {
        console.error(`[ERROR] Missing AES key for room ${roomId}`);
        return null;
    }
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

socket.on("user_left", (data) => appendMessage(null, data.msg, true));

// Handle WebSocket errors
socket.on("error", (error) => {
    console.error("[ERROR] WebSocket error:", error);
    alert("An error occurred with the WebSocket connection.");
});

const maxRooms = 5;

const allowedTypes = [
    "image/jpeg",
    "image/png",
    "application/pdf",
    "text/plain",
];

const maxChars = 150;

function updateCharCount() {
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const remaining = maxChars - [...messageInput.value].length;
    charCount.textContent = `${remaining} characters remaining`;
}
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
    const welcomePanel = document.querySelector(".welcome-panel");
    const chatPane = document.querySelector(".chat-pane");

    updateChatPanelVisibility(welcomePanel, chatPane);

    if (leaveRoomButton) {
        if (roomId && roomId !== "None") {
            leaveRoomButton.style.display = "block";
        } else {
            leaveRoomButton.style.display = "none";
        }
    }
    // Leave room button functionality
    if (leaveRoomButton) {
        leaveRoomButton.addEventListener("click", () => {
            socket.emit("leave", { user: username, roomId: roomId });
            sessionStorage.removeItem("room");
            window.location.href = "/dashboard";
            typingUsers.clear();
            renderTypingBanner();
        });
    }

    // Display username on the sidebar
    displayUsername(username);

    // Load existing rooms
    loadRooms();

    // Character count functionality
    messageInput.addEventListener("input", updateCharCount);

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
    let typingTimer;
    messageInput.addEventListener("input", () => {
        socket.emit("typing", {roomId, user: username, typing:true});
        clearTimeout(typingTimer);
        typingTimer = setTimeout(() =>
            socket.emit("typing", {roomId, user: username, typing:false}), 1500);
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
            formData.append("roomId", roomId);
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
                        url: `/uploads/${data.filename}?roomId=${roomId}`
                    });
                    const encryptedFileMsg = await encryptRoomMessage(roomId, fileMessage);
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
    sessionStorage.setItem("room", roomId);
});

// Function to display username on the sidebar
function displayUsername(username) {
    const usernameDisplay = document.createElement("p");
    usernameDisplay.textContent = `User: ${username}`;
    usernameDisplay.classList.add("username-display");
    document.querySelector(".sidebar").prepend(usernameDisplay);
}

function updateOnlineUsersList(users) {
    let onlineList = document.getElementById("onlineUsersList");
    
    if (!onlineList) {
        onlineList = document.createElement("div");
        onlineList.id = "onlineUsersList";
        document.querySelector(".sidebar").appendChild(onlineList);
    }

    // Clear current list
    onlineList.innerHTML = "<h3>Online Users:</h3>" + users.map(user => `<p>${user}</p>`).join("");
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

async function appendFileMessage(user, msgObject) {
    const messages = document.getElementById("messages");
    const messageElement = document.createElement("div");
    const timestamp = new Date().toLocaleTimeString();
    try {
        const response = await fetch(`/download/${msgObject.filename}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ roomId })
        });
        if (!response.ok) {
            throw new Error("Failed to download file.");
        }
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        let fileContent;
        if (/\.(jpg|jpeg|png|gif)$/i.test(msgObject.filename)) {
            fileContent = `<img src="${objectUrl}" alt="${msgObject.filename}" style="max-width:300px; border:1px solid #ccc;">`;
        } else {
            fileContent = `<a href="${objectUrl}" target="_blank">${msgObject.filename}</a>`;
        }
        messageElement.innerHTML = `<div>
            <strong>[${timestamp}] ${user}:</strong>
            <span>${fileContent}</span>
        </div>`;
        messages.appendChild(messageElement);
        messages.scrollTop = messages.scrollHeight;
    } catch (error) {
        console.error("[ERROR] File display failed:", error);
        messageElement.innerHTML = `<div><strong>[${timestamp}] ${user}:</strong> <em>Failed to load file</em></div>`;
        messages.appendChild(messageElement);
    }
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
            const evt = new Event("input", { bubbles: true });
            messageInput.dispatchEvent(evt);
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

window.addEventListener("load", () => {
    if (!sessionStorage.getItem("private_key")) {
        console.log("[DEBUG] Private key not found, fetching again...");
        fetchPrivateKey();
    }
});

window.addEventListener("beforeunload", () => {
    if (roomId && roomId !== "None") {
        socket.emit("leave", { user: username, roomId });
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
    const now = Date.now();
    if (now - lastMessageTime < 1000) {
        alert("You're sending messages too fast! Please wait.");
        return;
    }
    lastMessageTime = now;
    const encryptedMsg = await encryptMessage(message);
    socket.emit("message", { user: username, msg: encryptedMsg, roomId });
    messageInputElement.value = "";
    document.getElementById("charCount").textContent = "150 characters remaining";
}
