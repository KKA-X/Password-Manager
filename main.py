import tkinter
import customtkinter
from tkinter import messagebox
from random import randint, choice, shuffle
import pyperclip
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import os
import re
from getpass import getpass

# Global variable to track the state of displaying all passwords
display_all_pw = False

# ---------------------------- MASTER PASSWORD SETUP ------------------------------- #
MASTER_PASSWORD_FILE = "master_password.txt"

def get_master_password(private_key):
    try:
        with open(MASTER_PASSWORD_FILE, "rb") as file:
            encrypted_password = file.read()
            decrypted_password = private_key.decrypt(
                encrypted_password,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_password.decode()
    except FileNotFoundError:
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt master password: {e}")
        return None

def set_master_password(public_key, password):
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(MASTER_PASSWORD_FILE, "wb") as file:
        file.write(encrypted_password)

# ---------------------------- KEY GENERATION ------------------------------- #

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Save the private key
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(getpass("Set encryption password for keys: ").encode())
        ))
    
    # Save the public key
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Keys generated and saved.")

def load_keys():
    with open("private_key.pem", "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=getpass("Enter encryption password to load keys: ").encode(),
            backend=default_backend()
        )
    
    with open("public_key.pem", "rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
            backend=default_backend()
        )
    
    return private_key, public_key

# Generate keys if they don't exist
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    generate_keys()

private_key, public_key = load_keys()

# Setup master password if not set
if not os.path.exists(MASTER_PASSWORD_FILE):
    new_master_password = getpass("Set your master password: ")
    confirm_password = getpass("Confirm your master password: ")
    if new_master_password == confirm_password:
        set_master_password(public_key, new_master_password)
        print("Master password set successfully.")
    else:
        print("Passwords do not match. Please restart the application.")
        exit()

MASTER_PASSWORD = get_master_password(private_key)
if not MASTER_PASSWORD:
    print("Failed to retrieve master password. Please restart the application.")
    exit()

# ---------------------------- PASSWORD MANAGER FUNCTIONS ------------------------------- #

def encrypt_data(public_key, data):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(private_key, encrypted_data):
    try:
        decrypted_data = private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return None

def all_pw():
    global display_all_pw
    try:
        with open("Password.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No Data File Found.")
    else:
        if not display_all_pw:
            r_grid = 2  # Start displaying passwords below search widgets
            for w in data:
                e = data[w]['email']
                decrypted_password = decrypt_data(private_key, data[w]['password'])
                if decrypted_password:
                    website_label = customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{w}")
                    website_label.grid(row=r_grid, column=0, pady=5)
                    website_label.bind("<Button-3>", lambda e, text=w: pyperclip.copy(text))  # Bind right-click to copy website name

                    email_label = customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{e}")
                    email_label.grid(row=r_grid, column=1, pady=5)
                    email_label.bind("<Button-3>", lambda e, text=e: pyperclip.copy(text))  # Bind right-click to copy email

                    password_label = customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{decrypted_password}")
                    password_label.grid(row=r_grid, column=2, pady=5)
                    password_label.bind("<Button-3>", lambda e, text=decrypted_password: pyperclip.copy(text))  # Bind right-click to copy password

                    r_grid += 1
            display_all_pw = True
        else:
            # Clear existing widgets
            for widget in search_pw_tab.winfo_children():
                widget.destroy()
            # Re-add search and all passwords widgets
            customtkinter.CTkLabel(master=search_pw_tab, text="Search Website:").grid(row=0, column=0, pady=5, padx=10)
            search_ws_name = customtkinter.CTkEntry(master=search_pw_tab, width=200)
            search_ws_name.grid(row=0, column=1, pady=5)

            customtkinter.CTkButton(master=search_pw_tab, text="Search Password", command=lambda: search_pw(search_ws_name.get())).grid(row=1, column=0, pady=5, padx=10)
            customtkinter.CTkButton(master=search_pw_tab, text="All Passwords", command=all_pw).grid(row=1, column=1, pady=5, padx=10)
            display_all_pw = False

def search_pw(website):
    if website == "":
        messagebox.showinfo(title="Error", message="Please enter a website name.")
        return

    try:
        with open("Password.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No Data File Found.")
    else:
        # Clear existing widgets
        for widget in search_pw_tab.winfo_children():
            widget.destroy()

        customtkinter.CTkLabel(master=search_pw_tab, text="Search Website:").grid(row=0, column=0, pady=5, padx=10)
        search_ws_name = customtkinter.CTkEntry(master=search_pw_tab, width=200)
        search_ws_name.grid(row=0, column=1, pady=5)
        search_ws_name.insert(0, website)  # Set the entered website name

        customtkinter.CTkButton(master=search_pw_tab, text="Search Password", command=lambda: search_pw(search_ws_name.get())).grid(row=1, column=0, pady=5, padx=10)
        customtkinter.CTkButton(master=search_pw_tab, text="All Passwords", command=all_pw).grid(row=1, column=1, pady=5, padx=10)

        # Display search results
        r_grid = 2  # Start displaying passwords below search widgets
        for w, value in data.items():
            if website.lower() in w.lower():
                e = value['email']
                decrypted_password = decrypt_data(private_key, value['password'])
                if decrypted_password:
                    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{w}").grid(row=r_grid, column=0, pady=5)
                    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{e}").grid(row=r_grid, column=1, pady=5)
                    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"{decrypted_password}").grid(row=r_grid, column=2, pady=5)
                    r_grid += 1

def delete_password(delete_ws_name):
    try:
        with open("Password.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No Data File Found.")
    else:
        if delete_ws_name in data:
            del data[delete_ws_name]
            with open("Password.json", "w") as file:
                json.dump(data, file, indent=4)
            messagebox.showinfo(title="Success", message=f"Password for {delete_ws_name} deleted.")
            # Clear the current content in search_pw_tab
            for widget in search_pw_tab.winfo_children():
                widget.destroy()
            # Reload all passwords to refresh the UI
            all_pw()
            # Re-add search and all passwords widgets
            customtkinter.CTkLabel(master=search_pw_tab, text="Search Website:").grid(row=0, column=0, pady=5, padx=10)
            search_ws_name = customtkinter.CTkEntry(master=search_pw_tab, width=200)
            search_ws_name.grid(row=0, column=1, pady=5)

            customtkinter.CTkButton(master=search_pw_tab, text="Search Password", command=lambda: search_pw(search_ws_name.get())).grid(row=1, column=0, pady=5, padx=10)
            customtkinter.CTkButton(master=search_pw_tab, text="All Passwords", command=all_pw).grid(row=1, column=1, pady=5, padx=10)

        else:
            messagebox.showinfo(title="Error", message=f"No details for {delete_ws_name} exists.")

def update_password(update_ws_name, update_email, update_password):
    if update_ws_name == "" or update_email == "" or update_password == "":
        messagebox.showinfo(title="Error", message="One or more entities are empty!")
        return
    
    try:
        with open("Password.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No Data File Found.")
    else:
        if update_ws_name in data:
            encrypted_password = encrypt_data(public_key, update_password)
            data[update_ws_name] = {"email": update_email, "password": encrypted_password}
            with open("Password.json", "w") as file:
                json.dump(data, file, indent=4)
            messagebox.showinfo(title="Success", message=f"Password for {update_ws_name} updated.")
            all_pw()  # Refresh the All Passwords tab after update
        else:
            messagebox.showinfo(title="Error", message=f"No details for {update_ws_name} exists.")

        # Clear the current content in search_pw_tab
        for widget in search_pw_tab.winfo_children():
            widget.destroy()

        # Reload all passwords to refresh the UI
        all_pw()

        # Re-add search and all passwords widgets
        customtkinter.CTkLabel(master=search_pw_tab, text="Search Website:").grid(row=0, column=0, pady=5, padx=10)
        search_ws_name = customtkinter.CTkEntry(master=search_pw_tab, width=200)
        search_ws_name.grid(row=0, column=1, pady=5)

        customtkinter.CTkButton(master=search_pw_tab, text="Search Password", command=lambda: search_pw(search_ws_name.get())).grid(row=1, column=0, pady=5, padx=10)
        customtkinter.CTkButton(master=search_pw_tab, text="All Passwords", command=all_pw).grid(row=1, column=1, pady=5, padx=10)

def password_strength(password):
    length = len(password) >= 8
    digit = re.search(r"\d", password) is not None
    uppercase = re.search(r"[A-Z]", password) is not None
    lowercase = re.search(r"[a-z]", password) is not None
    special = re.search(r"[@$!%*?&]", password) is not None

    strength = sum([length, digit, uppercase, lowercase, special])

    if strength == 5:
        return "Strong"
    elif 3 <= strength < 5:
        return "Medium"
    else:
        return "Weak"

def pw_gen():
    entry_pw.delete(0, tkinter.END)
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
               'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    password_letters = [choice(letters) for _ in range(randint(8, 10))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

    password_list = password_numbers + password_symbols + password_letters
    shuffle(password_list)

    password_gen = "".join(password_list)
    entry_pw.insert(0, password_gen)
    pyperclip.copy(password_gen)
    
    # Update password strength label
    pw_strength_label.configure(text=f"Strength: {password_strength(password_gen)}")

def pw_found(w, e, p):
    # Clear existing labels
    for widget in search_pw_tab.winfo_children():
        widget.destroy()
    
    # Add new labels for found password
    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"Website: {w}").grid(row=0, column=0, pady=5)
    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"Email: {e}").grid(row=1, column=0, pady=5)
    customtkinter.CTkLabel(master=search_pw_tab, justify=tkinter.CENTER, text=f"Password: {p}").grid(row=2, column=0, pady=5)

def save_pass():
    website = entry_ws.get()
    email = entry_email.get()
    password = entry_pw.get()
    encrypted_password = encrypt_data(public_key, password)
    new_entry = {"email": email, "password": encrypted_password}

    if website == "" or email == "" or password == "":
        messagebox.showinfo(title="Password Manager", message="One or more entities are empty!")
    else:
        try:
            with open("Password.json", "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}

        if website in data:
            # An entry already exists for this website
            messagebox.showinfo(title="Password Manager", message=f"An entry already exists for {website}.")
        else:
            # Create new entry for this website
            data[website] = new_entry
            messagebox.showinfo(title="Password Manager", message=f"New entry created for {website}.")

            # Save updated data to file
            with open("Password.json", "w") as file:
                json.dump(data, file, indent=4)
        
        # Clear input fields after saving
        entry_ws.delete(0, tkinter.END)
        entry_email.delete(0, tkinter.END)
        entry_pw.delete(0, tkinter.END)
        
        # Update password strength label
        pw_strength_label.configure(text=f"Strength: {password_strength(password)}")

# ---------------------------- LOGIN FUNCTIONALITY ------------------------------- #

from tkinter import messagebox

def login():
    entered_password = login_entry.get()
    if entered_password == MASTER_PASSWORD:
        login_window.destroy()  # Close the login window
        messagebox.showinfo("Success", "Logged in successfully")  # Show success message
        open_main_window()  # Open the main window
    else:
        messagebox.showerror("Error", "Incorrect Master Password")

def open_main_window():
    global search_pw_tab, entry_ws, entry_email, entry_pw, pw_strength_label
    
    # Setting up the main window
    main_window = customtkinter.CTk()
    main_window.title("Password Manager")

    tabview = customtkinter.CTkTabview(master=main_window, width=300, height=300)
    tabview.pack(padx=20, pady=20)
    add_pw_tab = tabview.add("Add Password")
    search_pw_tab = tabview.add("Search Password")
    delete_pw_tab = tabview.add("Delete Password")
    update_pw_tab = tabview.add("Update Password")

    # Add Password Tab
    customtkinter.CTkLabel(master=add_pw_tab, text="Website:").grid(row=0, column=0, pady=5, padx=10)
    entry_ws = customtkinter.CTkEntry(master=add_pw_tab, width=200)
    entry_ws.grid(row=0, column=1, pady=5)

    customtkinter.CTkLabel(master=add_pw_tab, text="Email/Username:").grid(row=1, column=0, pady=5, padx=10)
    entry_email = customtkinter.CTkEntry(master=add_pw_tab, width=200)
    entry_email.grid(row=1, column=1, pady=5)

    customtkinter.CTkLabel(master=add_pw_tab, text="Password:").grid(row=2, column=0, pady=5, padx=10)
    entry_pw = customtkinter.CTkEntry(master=add_pw_tab, width=200)
    entry_pw.grid(row=2, column=1, pady=5)
    entry_pw.bind("<KeyRelease>", lambda event: update_pw_strength())

    pw_strength_label = customtkinter.CTkLabel(master=add_pw_tab, text="Strength: Unknown")
    pw_strength_label.grid(row=3, column=1, pady=5)

    customtkinter.CTkButton(master=add_pw_tab, text="Generate Password", command=pw_gen).grid(row=4, column=0, pady=5, padx=10)
    customtkinter.CTkButton(master=add_pw_tab, text="Save Password", command=save_pass).grid(row=4, column=1, pady=5, padx=10)

    # Search Password Tab
    customtkinter.CTkLabel(master=search_pw_tab, text="Search Website:").grid(row=0, column=0, pady=5, padx=10)
    search_ws_name = customtkinter.CTkEntry(master=search_pw_tab, width=200)
    search_ws_name.grid(row=0, column=1, pady=5)

    customtkinter.CTkButton(master=search_pw_tab, text="Search Password", command=lambda: search_pw(search_ws_name.get())).grid(row=1, column=0, pady=5, padx=10)
    customtkinter.CTkButton(master=search_pw_tab, text="All Passwords", command=all_pw).grid(row=1, column=1, pady=5, padx=10)

    # Delete Password Tab
    customtkinter.CTkLabel(master=delete_pw_tab, text="Website to Delete:").grid(row=0, column=0, pady=5, padx=10)
    delete_ws_name = customtkinter.CTkEntry(master=delete_pw_tab, width=200)
    delete_ws_name.grid(row=0, column=1, pady=5)

    customtkinter.CTkButton(master=delete_pw_tab, text="Delete Password", command=lambda: delete_password(delete_ws_name.get())).grid(row=1, column=0, columnspan=2, pady=5, padx=10)

    # Update Password Tab
    customtkinter.CTkLabel(master=update_pw_tab, text="Website to Update:").grid(row=0, column=0, pady=5, padx=10)
    update_ws_name = customtkinter.CTkEntry(master=update_pw_tab, width=200)
    update_ws_name.grid(row=0, column=1, pady=5)

    customtkinter.CTkLabel(master=update_pw_tab, text="Email/Username:").grid(row=1, column=0, pady=5, padx=10)
    update_email = customtkinter.CTkEntry(master=update_pw_tab, width=200)
    update_email.grid(row=1, column=1, pady=5)

    customtkinter.CTkLabel(master=update_pw_tab, text="New Password:").grid(row=2, column=0, pady=5, padx=10)
    update_pw = customtkinter.CTkEntry(master=update_pw_tab, width=200)
    update_pw.grid(row=2, column=1, pady=5)

    customtkinter.CTkButton(master=update_pw_tab, text="Update Password", command=lambda: update_password(update_ws_name.get(), update_email.get(), update_pw.get())).grid(row=3, column=0, columnspan=2, pady=5, padx=10)

    main_window.mainloop()

def update_pw_strength():
    password = entry_pw.get()
    strength = password_strength(password)
    pw_strength_label.configure(text=f"Strength: {strength}")

# ---------------------------- LOGIN UI SETUP ------------------------------- #
login_window = customtkinter.CTk()
login_window.title("Login")

customtkinter.CTkLabel(login_window, text="Master Password:").pack(pady=10)
login_entry = customtkinter.CTkEntry(login_window, show="*", width=200)
login_entry.pack(pady=5)

customtkinter.CTkButton(login_window, text="Login", command=login).pack(pady=10)

login_window.mainloop()

