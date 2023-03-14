import socket
import hashlib
import hmac
import threading

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

# Function to receive messages from the server and print them to the console
def receive_messages():
    while True:
        encrypted_message = client_socket.recv(1024).decode()
        if not encrypted_message:
            break
        if verify_message(encrypted_message):
            message = encrypted_message.split("::")[0]
            print(f'Received: {message}')

# Connect to the server
ip_address = 'localhost'
port = 8888
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((ip_address, port))

# Start a separate thread to receive messages from the server
threading.Thread(target=receive_messages).start()

# Send messages to the server and wait for user input
while True:
    message = input('> ')
    if message:
        encrypted_message = encrypt_message(message)
        client_socket.send(encrypted_message.encode())
