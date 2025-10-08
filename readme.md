# File Vault: Secure End-to-End Encrypted File Storage

![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14-336791?style=for-the-badge&logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)

**File Vault** is a full-stack web application designed for secure file storage and sharing. It features a robust end-to-end encryption model that ensures user files and passwords are encrypted on the client-side before ever being transmitted to the server.

---

## 📘 Project Description

### 🔐 What It Is

**File Vault** is a personal cloud storage solution where **security is the top priority**. Users can register, log in, upload files, manage them, and share them via public links.

All sensitive data is **encrypted and decrypted exclusively on the client-side**, making it a secure vault for your files.

### ⚙️ How It's Implemented

The application uses a modern tech stack and a multi-layered cryptographic model to ensure **end-to-end security**.

#### 🧰 Technology Stack

- **Backend**:  
  Written in **Go**, the API handles user authentication, file metadata management, and encrypted file blob handling.

- **Frontend**:  
  Built with **React**, the SPA handles encryption/decryption and interacts with the backend via API calls.

- **Database**:  
  **PostgreSQL** is used for metadata and encrypted blob storage.

- **Deployment**:  
  Fully containerized using **Docker** and orchestrated with **Docker Compose** for easy deployment.

---

## 🔒 Security Architecture

The application's security relies on a combination of **asymmetric (RSA)** and **symmetric (AES)** encryption.

### 🗝️ Password & Credential Encryption

- On login/registration, the **client fetches the server’s public RSA key**.
- The credentials are encrypted with this key before being sent.
- The server decrypts them using its **private RSA key**.
- This ensures **no plain-text passwords** are transmitted over the network.

### 🔑 Session & Payload Encryption

- Upon login, an **AES session key** is generated and encrypted using the user’s password.
- This session key is then used to encrypt/decrypt all further payloads (e.g., file lists, upload/download data).

### 📁 File Encryption

- Files are **encrypted in-browser** using the session key before uploading.
- The encrypted blob is stored on the server.
- On download, the **encrypted blob is sent back**, and decrypted **client-side** in the browser.

---

## ✨ Features

- ✅ **End-to-End Encryption (E2EE)**  
  Files are encrypted before upload and decrypted only after download — fully in the browser.

- 🔐 **Zero-Knowledge Architecture**  
  The server **never sees or stores your password** in plaintext.

- 🛡️ **Secure Authentication**  
  Uses **JWT-based auth tokens**.

- 🗃️ **Complete File Management**
  - Upload, download, view files securely.
  - View all uploaded files.
  - Delete files.

- 🔗 **File Access Control**
  - Set files as `PRIVATE` (only accessible to you) or `PUBLIC` (via shareable link).

- 📉 **Storage Optimization**
  - **Data deduplication** — identical files are stored only once.

- 🚫 **IP-Based Rate Limiting**
  - Backend includes **rate-limiting middleware** to prevent brute-force attacks.

- 📦 **Easy Deployment**
  - Fully **Dockerized** — run the entire stack with a single command.

---

## 📁 Project File Structure

```plaintext
.
├── .env.example            # Example environment file with required variables
├── docker-compose.yml      # Docker Compose file to build and run all services
│
├── backend/
│   ├── Dockerfile              # Build instructions for the Go backend
│   ├── server.go                 # Entry point with HTTP router and middleware
│   ├── go.mod                  # Go module definitions
│   │
│   ├── functions/
│   │   └── functions.go        # API logic (Login, UploadFile, etc.)
│   │
│   └── database/
│       ├── database.go         # DB queries (e.g., GetUserData, InsertFile)
│       └── database.sql            # DB schema for Docker Compose initialization
│
└── frontend/
    ├── Dockerfile              # Build instructions for the React frontend
    ├── package.json            # NPM scripts and dependencies
    │
    ├── public/
    │   └── index.html          # HTML entry point
    │
    └── src/
        ├── index.js            # React app entry point
        ├── App.js              # Main app component and routing
        │
        ├── api.js              # Client-side API calls and crypto logic
        │
        ├── components/         # Reusable components (Login, Dashboard, etc.)
        │
        └── pages/              # Page-level components for UI structure
