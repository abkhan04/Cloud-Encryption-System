# 🔐 Secure File Sharing Web App

This project is a secure, web-based file sharing platform built with Flask. It enables user registration, login, file encryption, and sharing with a selected group using hybrid cryptography. Uploaded files are securely stored in Dropbox, encrypted individually for each group member.

## ✨ Features

- User registration with certificate generation (self-signed).
- Hybrid encryption: symmetric (Fernet) + asymmetric (RSA).
- Encrypted file upload and download via Dropbox.
- Group-based file sharing.
- Simple web UI with Flask and HTML templates.

---

## 🚀 Getting Started

### 🔧 Prerequisites

Make sure you have the following installed:

- Python 3.8+
- Dropbox API key
- `pip` (Python package manager)

### 📦 Installation

1. **Clone the repository**

```bash
git clone https://github.com/avkhan/Cloud-Encryption-System.git
cd Cloud-Encryption-System

2. **Create a virtual environment (optional but recommended)**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

Add this to your `requirements.txt`:

```
flask
python-dotenv
dropbox
cryptography
```

4. **Setup environment variables**

Create a `.env` file in the project root:

```env
DROPBOX_API_KEY=your_dropbox_access_token_here
```

---

## 🏁 Running the App

```bash
python main.py
```

Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 👤 Test Users

On launch, the app creates two test users:
- **Username**: `test`, **Password**: `test`
- **Username**: `test2`, **Password**: `test`

They are already in each other’s groups for easy file sharing testing.

---

## 📁 Project Structure

```
.
├── main.py             # Main application logic
├── templates/          # HTML templates (login, register, dashboard)
├── .env                # Environment variables
└── requirements.txt    # Python dependencies
```

> ⚠️ This app uses in-memory storage — restarting the app resets users and uploaded file data.

---

## 🔒 Security Notes

- Uses hybrid cryptography: files encrypted with Fernet, keys with RSA.
- Generates self-signed certificates per user.
- Validates public keys using certificates before encrypting.
