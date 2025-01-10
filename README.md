
# Password Manager

A **secure and user-friendly Password Manager** designed to help individuals store and manage their passwords offline. Built with Python, tkinter, and cryptography, this mini-project focuses on providing a reliable solution for password management without internet dependency.

## Features

- **Offline Application:** Ensures data security by operating independently of internet connectivity.
- **Secure Storage:** Encrypts passwords using advanced cryptographic techniques (e.g., RSA).
- **Master Password:** Protects access to all stored passwords with a master password.
- **Password Management:** Add, update, delete, and search for saved passwords.
- **User-Friendly Interface:** Aesthetic dark-themed GUI designed with `customtkinter`.
- **Password Strength Indicator:** Helps users choose strong passwords.
- **Data Encryption:** Uses RSA encryption for storing sensitive data.
- **Error Handling:** Robust mechanisms to handle invalid inputs and operations.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/password-manager.git
   cd password-manager
   ```

2. **Install Dependencies:**
   Ensure you have Python installed on your system, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application:**
   ```bash
   python main.py
   ```

## Usage

1. Set up the master password during the first run.
2. Log in with your master password.
3. Use the intuitive interface to:
   - Add new website credentials.
   - Search for saved passwords.
   - Update or delete entries.
4. Enjoy secure offline password management.

## Snapshots

### Login Page
![image](https://github.com/user-attachments/assets/0e479a9a-4217-4db3-9ffe-f9b4616c480f)

### Add Password Tab - Adding and saving Credentials
![image](https://github.com/user-attachments/assets/aacd14cb-1573-4c6b-96f0-62808f246b77)

### Search Password Tab - Searching for Stored Passwords
![image](https://github.com/user-attachments/assets/04a1a05d-c2d1-4610-ac90-b0035b7063a9)

### Delete Password Tab - Deleting Stored Password
![image](https://github.com/user-attachments/assets/f19dba8b-f088-4c61-bbc9-58b759e0cefa)

### Update Password Tab - Updating the Existing Password
![image](https://github.com/user-attachments/assets/4d19efe0-61db-45e9-bf92-8871763027b4)

## Requirements

### Software
- Python 3.8 or above
- Libraries: `tkinter`, `customtkinter`, `cryptography`

### Hardware
- Intel Core i3 or above
- 4GB RAM (recommended)

## Security

- Passwords are encrypted using RSA public-key encryption.
- Master password is stored securely after encryption.

## Motivation

This project aims to provide an offline, secure solution for managing the growing number of passwords individuals use daily. It emphasizes simplicity, security, and user independence.

## References

- [Python Documentation](https://docs.python.org/3/)
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
- [Cryptography Documentation](https://cryptography.io/en/latest/)
- [CustomTkinter](https://pypi.org/project/customtkinter/)
- [Stack Overflow](https://stackoverflow.com/)


