# 🔐 CLI Password Manager

A secure, Python-based Command-Line Password Manager designed to store and manage website credentials locally using an encrypted vault.

The application allows users to add, retrieve, list, and delete saved credentials while protecting sensitive information with master password authentication. It also includes login attempt protection and master password management.

## ✨ Features

- **Encrypted Password Vault:** Stores credentials in a local encrypted vault.
- **Master Password Authentication:** Protects access to stored credentials.
- **Add Credentials:** Save website URLs, usernames, and passwords.
- **Retrieve Credentials:** Retrieve saved credentials for a specific website.
- **List Websites:** Display all saved websites.
- **Delete Credentials:** Remove stored credentials with confirmation.
- **Login Lockout Protection:** Tracks failed authentication attempts and implements lockout protection.
- **Change Master Password:** Change the master password and re-encrypt stored entries.
- **Hidden Password Input:** Hides password input in the terminal.

## 🛠️ Tech Stack

- Python
- Command Line Interface (CLI)
- JSON-based local storage
- Password encryption

## 📂 Project Structure

```text
cli-password-manager/
│
├── main.py
│
├── password_manager/
│   ├── exceptions.py
│   ├── lockout.py
│   ├── storage.py
│   └── vault.py
│
├── requirements.txt
└── README.md
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone YOUR_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd cli-password-manager
```

### 3. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

**macOS / Linux**
```bash
source .venv/bin/activate
```

**Windows**
```bash
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## 🚀 Usage

### 1. Initialize a New Vault

```bash
python main.py init
```

Create a custom vault:

```bash
python main.py --vault my_vault.json init
```

### 2. Add Credentials

```bash
python main.py add
```

Enter the website URL, username/email, and account password when prompted.

### 3. Retrieve Credentials

```bash
python main.py get example.com
```

### 4. List Saved Websites

```bash
python main.py list
```

### 5. Delete Credentials

```bash
python main.py delete example.com
```

### 6. Change Master Password

```bash
python main.py change-master
```

## 🔒 Security Features

- Master password-based authentication.
- Encrypted local credential storage.
- Failed login attempt tracking.
- Lockout protection against repeated authentication failures.
- Hidden password input.
- Re-encryption of stored entries when changing the master password.

## ⚠️ Important Notes

- Keep your master password safe.
- Losing your master password may result in permanent loss of access to your credentials.
- Always maintain a secure backup of your encrypted vault.
- Retrieved passwords are displayed in the terminal.
- Never upload actual vault files or sensitive credentials to GitHub.

## 🎯 Project Objective

The objective of this project is to build a practical password management application while learning Python, encryption, authentication, local storage, exception handling, and command-line application development.

---

**Built with Python 🐍**
