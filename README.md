# Secure-File-Transfer-Application-GUI-Based-
A hybrid-encryption secure file transfer system built using Python. Includes a GUI Client and GUI Server using Tkinter. Files are encrypted with AES-256 GCM, the AES key is encrypted using RSA-2048 OAEP, and transferred securely over sockets.
# 🔐 Secure File Transfer Application (GUI-Based)
A secure, hybrid encryption–based file transfer system with a graphical interface, built using Python.  
Supports encrypted communication between a Client and Server using AES-GCM and RSA-OAEP.

This project was developed as part of an MSc Digital Forensics & Information Security mini-project.

## 🚀 Features

### 🔒 Security Features
- **Hybrid Encryption**
  - Files encrypted using **AES-256 GCM**
  - AES key protected using **RSA-2048 OAEP**
- **RSA Key Pair Automatically Generated** on server startup
- **Integrity Verification**
  - Server computes a SHA-256 hash for authenticity
- **Authenticated Encryption**
  - AES-GCM provides confidentiality + integrity

### 🖥 GUI Features
- Built with **Tkinter**
- Easy-to-use **Client** and **Server** interfaces
- Server shows real-time logs:
  - Key generation  
  - Incoming connections  
  - File decryption status  
  - Stored file path + SHA-256 hash  
- Client GUI allows:
  - Selecting server public key  
  - Choosing file to send  
  - Viewing server ACK response  

### 📡 Network Features
- TCP Socket communication
- Custom message framing (length-prefixed header)
- Supports any file type: documents, images, audio, zip files, etc.


