import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os

def encrypt(plain_text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode()

def decrypt(cipher_text, key):
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()
    return plain_text.decode()

def handle_encrypt():
    plain_text = entry_plain_text.get()
    key = entry_key.get()

    if len(key) != 32:
        messagebox.showerror("Error", "Key must be 32 characters long (256-bit).")
        return

    cipher_text = encrypt(plain_text, key.encode())
    entry_cipher_text.delete(0, ctk.END)
    entry_cipher_text.insert(0, cipher_text)

def handle_decrypt():
    cipher_text = entry_cipher_text.get()
    key = entry_key.get()

    if len(key) != 32:
        messagebox.showerror("Error", "Key must be 32 characters long (256-bit).")
        return

    try:
        plain_text = decrypt(cipher_text, key.encode())
        entry_plain_text.delete(0, ctk.END)
        entry_plain_text.insert(0, plain_text)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed. Please check the key and cipher text.")

def toggle_password_visibility():
    if entry_key.cget("show") == "*":
        entry_key.configure(show="")
        btn_show_password.configure(text="Hide Password")
    else:
        entry_key.configure(show="*")
        btn_show_password.configure(text="Show Password")

ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

window = ctk.CTk()
window.title("AES Encryption/Decryption")

lbl_plain_text = ctk.CTkLabel(window, text="Plain Text")
lbl_plain_text.grid(row=0, column=0, padx=10, pady=10)
entry_plain_text = ctk.CTkEntry(window, width=300)
entry_plain_text.grid(row=0, column=1, padx=10, pady=10)

lbl_key = ctk.CTkLabel(window, text="Key (32 characters)")
lbl_key.grid(row=1, column=0, padx=10, pady=10)
entry_key = ctk.CTkEntry(window, width=300, show="*")
entry_key.grid(row=1, column=1, padx=10, pady=10)

lbl_cipher_text = ctk.CTkLabel(window, text="Cipher Text")
lbl_cipher_text.grid(row=2, column=0, padx=10, pady=10)
entry_cipher_text = ctk.CTkEntry(window, width=300)
entry_cipher_text.grid(row=2, column=1, padx=10, pady=10)

btn_show_password = ctk.CTkButton(window, text="Show Password", command=toggle_password_visibility)
btn_show_password.grid(row=1, column=2, padx=10, pady=10)

button_encrypt = ctk.CTkButton(window, text="Encrypt", command=handle_encrypt)
button_encrypt.grid(row=3, column=0, padx=10, pady=10)

button_decrypt = ctk.CTkButton(window, text="Decrypt", command=handle_decrypt)
button_decrypt.grid(row=3, column=1, padx=10, pady=10)

window.mainloop()
