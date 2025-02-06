let username = sessionStorage.getItem("username");

let socket = io.connect("ws://" + location.host);

socket.on("connect", function() {
    console.log("Connected to WebSocket server!");
    socket.emit("join", { user: username });
});

function sendMessage() {}
