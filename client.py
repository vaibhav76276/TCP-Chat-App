import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Globals
key = b'0123456789abcdef0123456789abcdef'
iv = b'abcdef9876543210'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# GUI Setup
root = tk.Tk()
root.title("Secure Chat Client")
username = simpledialog.askstring("Username", "Choose a unique username")
server_ip = simpledialog.askstring("Server IP", "Enter server IP", initialvalue="127.0.0.1")
sock.connect((server_ip, 12345))

text_area = scrolledtext.ScrolledText(root, state='disabled')
text_area.pack(padx=10, pady=10, fill='both', expand=True)

entry = tk.Entry(root)
entry.pack(side='left', fill='x', expand=True, padx=(10, 0))
send_btn = tk.Button(root, text="Send")
send_btn.pack(side='left', padx=10)

def encrypt(message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = message + b' ' * (16 - len(message) % 16)
    return encryptor.update(padded) + encryptor.finalize()

def send_data(msg):
    encrypted = encrypt(msg.encode())
    sock.send(encrypted)

def send_msg():
    msg = f"{username}: {entry.get()}"
    send_data(msg)
    entry.delete(0, tk.END)

def receive():
    while True:
        try:
            msg = sock.recv(1024).decode()
            display(msg)
        except:
            break

def display(msg):
    text_area.config(state='normal')
    text_area.insert(tk.END, msg + '\n')
    text_area.yview(tk.END)
    text_area.config(state='disabled')

# Bind send button
send_btn.config(command=send_msg)

# Send username on connect
send_data(f"USERNAME:{username}")

# Start receiving thread
threading.Thread(target=receive, daemon=True).start()

# Run GUI
root.mainloop()
