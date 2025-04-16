import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")

        self.key = b'0123456789abcdef0123456789abcdef'
        self.iv = b'abcdef9876543210'

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = simpledialog.askstring("Username", "Choose a unique username")
        self.server_ip = simpledialog.askstring("Server IP", "Enter server IP", initialvalue="127.0.0.1")
        self.sock.connect((self.server_ip, 12345))

        # GUI
        self.text_area = scrolledtext.ScrolledText(master, state='disabled')
        self.text_area.pack(padx=10, pady=10, fill='both', expand=True)

        self.entry = tk.Entry(master)
        self.entry.pack(side='left', fill='x', expand=True, padx=(10, 0))
        self.send_btn = tk.Button(master, text="Send", command=self.send_msg)
        self.send_btn.pack(side='left', padx=10)

        self.send_username()

        threading.Thread(target=self.receive, daemon=True).start()

    def encrypt(self, message):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = message + b' ' * (16 - len(message) % 16)
        return encryptor.update(padded) + encryptor.finalize()

    def send_username(self):
        encrypted = self.encrypt(f"USERNAME:{self.username}".encode())
        self.sock.send(encrypted)

    def send_msg(self):
        message = f"{self.username}: {self.entry.get()}"
        encrypted = self.encrypt(message.encode())
        self.sock.send(encrypted)
        self.entry.delete(0, tk.END)

    def receive(self):
        while True:
            try:
                message = self.sock.recv(1024).decode()
                self.display(message)
            except:
                break

    def display(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + '\n')
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    ChatClient(root)
    root.mainloop()
