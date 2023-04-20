import socket
import threading
import hashlib
import hmac

# Generate a secret key for message encryption
SECRET_KEY = b"mysecretkey"

# Function to encrypt a message using HMAC-SHA256
def encrypt_message(message):
    digest = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return f"{message}::{digest}"

# Function to verify the integrity of an encrypted message
def verify_message(encrypted_message):
    message, digest = encrypted_message.split("::")
    expected_digest = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return digest == expected_digest

# Function to handle client connections
def handle_client(client_socket, client_address):
    print(f"New connection from {client_address}")
    while True:
        encrypted_message = client_socket.recv(1024).decode()
        if not encrypted_message:
            break
        if verify_message(encrypted_message):
            message = encrypted_message.split("::")[0]
            print(f"Received from {client_address}: {message}")
            # Forward the message to all connected clients (except the sender)
            for sock, addr in clients:
                if sock != client_socket:
                    encrypted_message = encrypt_message(message)
                    sock.send(encrypted_message.encode())
    print(f"Connection closed with {client_address}")
    clients.remove((client_socket, client_address))
    client_socket.close()

# Initialize the server socket
ip_address = 'localhost' # Type in the server's IP address
port = 8888
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((ip_address, port))
server_socket.listen()
print("Server listening on http://{0}:{1}".format(ip_address, port))

# Initialize a list of connected clients
clients = []

# Wait for incoming client connections
while True:
    client_socket, client_address = server_socket.accept()
    clients.append((client_socket, client_address))
    # Start a new thread to handle the client connection
    threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
