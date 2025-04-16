import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ChatServer:
    def __init__(self, port=12345):
        self.clients = {}
        self.key = b'0123456789abcdef0123456789abcdef'
        self.iv = b'abcdef9876543210'

        self.host = socket.gethostbyname(socket.gethostname())  # 🟢 Dynamic IP
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, port))
        self.server.listen()
        print(f"Server started on {self.host}:{port}")

    def encrypt(self, message):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = message + b' ' * (16 - len(message) % 16)
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def broadcast(self, message, exclude=None):
        for client in self.clients:
            if client != exclude:
                try:
                    client.send(message.encode())
                except:
                    self.remove_client(client)

    def remove_client(self, client):
        if client in self.clients:
            username = self.clients[client]
            print(f"{username} disconnected.")
            self.broadcast(f"{username} left the chat.")
            client.close()
            del self.clients[client]

    def handle_client(self, client):
        try:
            encrypted = client.recv(1024)
            decrypted = self.decrypt(encrypted).decode('utf-8').rstrip()
            if decrypted.startswith("USERNAME:"):
                username = decrypted.split(":", 1)[1]
                self.clients[client] = username
                self.broadcast(f"{username} joined the chat.")
                print(f"{username} connected.")
            else:
                return

            while True:
                encrypted_msg = client.recv(1024)
                if not encrypted_msg:
                    break
                decrypted = self.decrypt(encrypted_msg).decode('utf-8').rstrip()
                print(f"[Encrypted]: {encrypted_msg}")
                print(f"[Decrypted]: {decrypted}")
                self.broadcast(decrypted, exclude=None)
        except Exception as e:
            print("Error:", e)
        finally:
            self.remove_client(client)

    def start(self):
        while True:
            client, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    ChatServer().start()
