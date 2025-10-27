# 🔐 FileGuard: Secure File Encryption & Integrity Verification

**Author:** SANTHOSH L  
**License:** MIT License  

---

## 📘 Overview
**FileGuard** is a Python-based encryption tool that provides secure AES-256 encryption and SHA-256 integrity verification for your files.  
It includes a simple **GUI interface** built with Tkinter that allows users to generate keys, encrypt files, decrypt files, and verify data integrity — all in one place.

This project demonstrates real-world cybersecurity principles including **data confidentiality, integrity, and secure cryptographic practices**.

---

## ✨ Features
- 🔑 **AES-256 Encryption** using Python’s `cryptography` library  
- 🧩 **SHA-256 Hash Verification** for file integrity  
- 💻 **GUI Interface** using Tkinter  
- 📂 **Automatic Folder Management** for `encrypted/` and `decrypted/` files  
- ⚠️ **Integrity Check Alerts** to detect tampering  
- 🧠 Clean, simple interface for easy demonstration and learning

---

## 🛠️ Tools & Technologies Used
- **Python 3.10+**
- **cryptography** library
- **hashlib** (for SHA-256)
- **Tkinter** (for GUI)

---

## ⚙️ Installation & Setup

Follow these simple steps to install and run FileGuard on your system 👇

🪟 For Windows Users
1️⃣ Clone the Repository

Open Command Prompt or PowerShell, and run:

git clone  https://github.com/Santhosh595/FileGuard-AES-SHA256.git
cd FileGuard-AES-SHA256

2️⃣ Check if Python is Installed

Run:

python --version


✅ You should see something like Python 3.10.0 or higher.
If not, download it from python.org/downloads
.

3️⃣ Install the Required Packages

Run this command to install all dependencies:

pip install -r requirements.txt


This installs:

cryptography → For AES-256 encryption/decryption

tk → For GUI support

4️⃣ Run the Application

Once setup is done, start the app:

python main.py

5️⃣ Use the GUI

You’ll see the FileGuard window open. Now:

🗝️ Click Generate Key – creates secret.key (only needed once)

📄 Click Browse File – choose the file you want to secure

🔒 Click Encrypt File – your file is encrypted and saved in /encrypted/

🔓 Click Decrypt File – decrypts the file and verifies integrity using SHA-256