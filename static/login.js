document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault();

    const formData = new FormData(this);

    fetch("/login", {
        method: "POST",
        headers: {
            "X-Requested-With": "XMLHttpRequest"
        },
        body: formData
    })
    .then(response => {
        if (!response.ok) throw new Error("Server error: " + response.status);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            sessionStorage.setItem("username", formData.get("username"));
            window.location.href = "/dashboard";
        } else {
            alert(data.message);
        }
    })
    .catch(err => {
        alert("Request failed: " + err.message);
        console.error("[ERROR]", err);
    });    
});

document.addEventListener("DOMContentLoaded", () => {
    if (new URLSearchParams(window.location.search).get("clearStorage") === "1") {
        console.log("[INFO] Clearing sessionStorage on logout");
        sessionStorage.clear();
    }

    const banner = document.getElementById("acctBanner");
    if (banner) {
      setTimeout(() => banner.remove(), 6000);
      document.getElementById("loginForm")
              .addEventListener("submit", () => banner.remove());
    }
  });