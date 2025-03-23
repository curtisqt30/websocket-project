# **CurtisConnect – Secure WebSocket Chat Application**

**Author:** Curtis Quan-Tran

## **Introduction**

**CurtisConnect** is a secure, web-based real-time chat application leveraging **WebSockets over SSL (WSS)** to provide encrypted and reliable communication. The application exclusively allows secure WebSocket connections (`wss://`) and proactively blocks insecure connections (`ws://`). Designed with security at its core, CurtisConnect includes robust security measures such as rate-limiting, inactivity monitoring, brute-force protection, and encrypted data handling.

## **Key Features**

- **Real-time Communication:** Instant messaging with seamless room navigation.
- **Secure WebSocket:** Supports only `wss://` connections, blocking all insecure protocols.
- **Advanced Encryption:**
  - **AES-256-GCM:** Protects message content and file transfers, encrypting data in transit and at rest.
  - **RSA-4096 with OAEP:** Securely handles AES key exchanges.
- **Secure Authentication:** User credentials stored securely using bcrypt hashing (with salting).
- **Rate Limiting:** Restricts users to one message per second to prevent abuse.
- **Inactivity Monitoring:** Sessions expire after 30 minutes of inactivity.
- **Rich Media and Formatting:** Supports file sharing, markdown-rich text, and emoji integration via Emoji Mart.
- **Room Management:** Easy-to-use interface for creating and joining chat rooms using unique Room IDs.

## **Security & Infrastructure**

- **SSL Certification:** Trusted certificates obtained via Let's Encrypt using Certbot.
- **Brute Force Protection:** Blocks IP addresses for 5 minutes after 3 failed login attempts.
- **Comprehensive Logging:** Detailed logging including IP addresses, timestamps, and user activity.
- **Hosting Environment:**
  - Hosted securely on a Raspberry Pi server.
  - Managed DNS via Cloudflare, featuring Geo-blocking and advanced bot protection.
  - SSH security enhancements including key-based authentication and custom ports.
  - Firewall configured with strict UFW rules and monitored using Fail2ban and rkhunter.

## **Supported File Types for Sharing**

- **TXT, PDF, PNG, JPG, JPEG, GIF**  
(Maximum file size: **8 MB**)

## **Running the Application**
Access the application securely at:

```
https://curtisqt.com/
```

## **Future Enhancements**

- Advanced input validation and sanitization.
- Enhanced user activity tracking.
- Room-specific passwords.
- Further front-end UI improvements.
- Administrative scripts for secure log management.

## **AI Assistance & Contributions**

AI tools contributed significantly in:

- **Frontend Development:** UI design, debugging JavaScript and CSS.
- **Backend Development:** Improving key management and session handling.
- **Security Guidance:** Recommendations for encryption standards and Raspberry Pi security hardening.
- **Documentation:** Professional structure, tone, and wording improvements.

---