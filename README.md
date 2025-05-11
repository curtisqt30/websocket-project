# CurtisConnect – Secure WebSocket Chat Application  
**Author :** Curtis Quan-Tran | **Last update :** 11 May 2025 | [GitHub repo](https://github.com/curtisqt30/websocket-project)

---

## 1  Introduction  

CurtisConnect is a **cloud-hosted, end-to-end encrypted chat platform**. All traffic uses **secure WebSockets (WSS)**; any plain-text `ws://` attempt is refused by the client.  Messages and file-blobs are encrypted in-browser with **AES-256-GCM**; per-room keys are exchanged with **RSA-4096 + OAEP**. Because encryption happens before data leave the browser, neither the Flask server nor Firebase Storage can decrypt user content.

---

## 2  Technology Stack  

| Layer | Components |
|-------|------------|
| **Frontend** | Vanilla JS • Markdown rendering (`marked.js`) • Emoji-Mart picker |
| **Backend / realtime** | Python • Flask • Flask-SocketIO (eventlet) • Flask-Sessions |
| **Transport security** | Render-managed **Let’s Encrypt** TLS → automatic HTTPS / WSS |
| **Cryptography** | AES-256-GCM (content) • RSA-4096 + OAEP (key exchange) |
| **Authentication** | Username / password hashed with **bcrypt + per-user salt** |
| **Database** | PostgreSQL (free Render tier) – users, room metadata, encrypted history |
| **File storage** | Firebase Storage – server uploads AES blobs, client downloads **24 h signed URLs** |
| **Ops / uptime** | Render web service + Postgres • UptimeRobot pings `/ping` every 10 min |
| **Security headers** | CSP, HSTS, Referrer-Policy, Permissions-Policy, X-Frame-Options |

*(Phase-2’s Raspberry-Pi + Nginx stack was retired; Render now supplies HTTPS for us.)*

---

## 3  Changes Since Phase 2  

| Area | Phase 2 (old) | Phase 3 (new) |
|------|---------------|---------------|
| **Hosting / domain** | Raspberry Pi behind Nginx at `curtisqt.com` | Fully managed on **Render** → `websocket-project-5mug.onrender.com` |
| **TLS certificates** | LE cert issued manually | LE cert auto-issued by Render |
| **Cloud proxy** | Cloudflare (bot protection, geo-rules) | Cloudflare removed; Render serves HTTPS directly |
| **File storage** | Stored on local disk | Stored in **Firebase Storage** with signed URLs |
| **Password hashing** | SHA-256 (unsalted) | **bcrypt + salt** |
| **Registration security** | None | **Google reCAPTCHA v2** |
| **Message limit** | 50 chars | **150 chars** |
| **Idle timeout** | 40 s + warning | **30 min**, no banner |
| **Logging** | Verbose SSL/404 noise | Noise suppressed |
| **UI** | Simple chat page | New dashboard sidebar, room list, “Leave Room” button |

--- 

## 4  User Guide (quick start)

> **URL:** <https://websocket-project-5mug.onrender.com>

1. **Register / Login**  
   * Click **Register**, solve reCAPTCHA, choose username + password.  
   * Existing users → **Login**.

2. **Rooms**  
   * Sidebar → **Create Room** (auto 4-char ID) or **Join Room** (enter ID).  
   * **Leave Room** button returns to lobby.

3. **Chat**  
   * End-to-end encrypted messages (150 chars max, 1 msg / sec).  
   * Supports Markdown formatting and Emoji-Mart picker.

4. **File sharing**  
   * TXT, PDF, PNG, JPG, JPEG, GIF ≤ 8 MB.  
   * Encrypted with AES-256-GCM; served via 24 h signed link.

5. **Logout** – click **Log Out** or close the browser tab.

---

## 5  Security Highlights  

* **AES-256-GCM** for all content; **RSA-4096 + OAEP** for key exchange  
* **bcrypt + salt** credential storage in Postgres  
* **Brute-force protection** – 3 failed logins ⇒ IP blocked 5 min  
* **Rate-limit** – 1 message / sec per user  
* **Google reCAPTCHA** on registration  
* Strict security headers (CSP, HSTS, etc.)  
* Server & cloud storage never see plaintext of messages or files

---

## 6  Hosting & Infrastructure  

* **Render** service (256 MB RAM · 0.1 CPU) + free **Postgres** (1 GB)  
* **Firebase Storage** for encrypted blobs; 24 h signed URLs  
* **UptimeRobot** pings `/ping` every 10 minutes  
* Render auto-renews Let’s Encrypt certs → SSL Labs **A+**  
* All security headers set directly in `app.py` → securityheaders.com **A**

---

## 7  Roadmap / Future Improvements  

* Input validation / XSS sanitisation  
* Reliable global & in-room rosters (work-in-progress)  
* Room options: password protection, size limit, friendly names  
* Scrollback / chat history for late joiners  
* Richer log viewer inside Render dashboard

---

## 8  AI Assistance & Credits  

| Area | AI contribution |
|------|-----------------|
| **Frontend** | Suggested dashboard layout, CSS tweaks, attempted roster logic |
| **Backend** | Helped debug key-management, advised Render ↔ Firebase ↔ Postgres integration |
| **Security** | Recommended OAEP, extra HTTP headers, log-noise suppression |
| **Docs** | Assisted with structure, wording and table formatting |

---

*© 2025 Curtis Quan-Tran* 