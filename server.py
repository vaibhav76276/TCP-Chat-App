import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Globals
clients = {}
key = b'0123456789abcdef0123456789abcdef'
iv = b'abcdef9876543210'

host = socket.gethostbyname(socket.gethostname())
port = 12345
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

print(f"Server started on {host}:{port}")

def encrypt(message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = message + b' ' * (16 - len(message) % 16)
    return encryptor.update(padded) + encryptor.finalize()

def decrypt(data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def broadcast(message, exclude=None):
    for client in clients:
        if client != exclude:
            try:
                client.send(message.encode())
            except:
                remove_client(client)

def remove_client(client):
    if client in clients:
        username = clients[client]
        print(f"{username} disconnected.")
        broadcast(f"{username} left the chat.")
        client.close()
        del clients[client]

def handle_client(client):
    try:
        encrypted = client.recv(1024)
        decrypted = decrypt(encrypted).decode().rstrip()
        if decrypted.startswith("USERNAME:"):
            username = decrypted.split(":", 1)[1]
            clients[client] = username
            broadcast(f"{username} joined the chat.")
            print(f"{username} connected.")
        else:
            return

        while True:
            encrypted_msg = client.recv(1024)
            if not encrypted_msg:
                break
            decrypted = decrypt(encrypted_msg).decode().rstrip()
            print(f"[Encrypted]: {encrypted_msg}")
            print(f"[Decrypted]: {decrypted}")
            broadcast(decrypted)
    except Exception as e:
        print("Error:", e)
    finally:
        remove_client(client)

def start_server():
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

# Start the server
start_server()
