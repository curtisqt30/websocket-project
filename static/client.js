let username = sessionStorage.getItem("username");
if (!username) {
    window.location.href = "/";
}

let socket = io.connect("ws://" + location.host);

socket.on("connect", function() {
    console.log("Connected to WebSocket server!");
    socket.emit("join", { user: username });
});

socket.on("message", function(data) {
    console.log("Received message:", data); 
    let messages = document.getElementById("messages");

    if (messages) {
        let messageElement = document.createElement("p");
        messageElement.innerText = `${data.user}: ${data.msg}`;
        messages.appendChild(messageElement);
    } else {
        console.error("Message container not found!");
    }
});

function sendMessage() {
    let messageInput = document.getElementById("messageInput");
    let msg = messageInput.value.trim();

    if (msg !== "") {
        console.log("Sending message:", msg);
        socket.emit("message", { user: username, msg: msg });
        messageInput.value = "";
    }
}
