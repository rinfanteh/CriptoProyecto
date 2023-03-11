import socket
from cryptography.fernet import Fernet

# Generate a unique key for the encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Set up the socket for communication
HOST = socket.gethostbyname(socket.gethostname())
PORT = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()

# Wait for a connection from another machine
print(f"Listening for connections on {HOST}:{PORT}...")
conn, addr = s.accept()
print(f"Connected by {addr}")

# Exchange encryption keys
conn.send(key)
their_key = conn.recv(1024)

# Start the chat session
while True:
    # Wait for a message from the other machine
    cipher_text = conn.recv(1024)
    plain_text = cipher_suite.decrypt(cipher_text)
    message = plain_text.decode()
    print(f"Received message: {message}")

    # Send a message to the other machine
    message = input("Type a message: ")
    plain_text = message.encode()
    cipher_text = cipher_suite.encrypt(plain_text)
    conn.send(cipher_text)
