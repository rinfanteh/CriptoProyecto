import socket
import hashlib
import hmac
import threading
import tkinter as tk


# Generate a secret key for message encryption
SECRET_KEY = b"mysecretkey"

# Function to encrypt a message using HMAC-SHA256
def encrypt_message(message):
    '''This function is to encrypt the message'''
    digest = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return f"{message}::{digest}"

# Function to verify the integrity of an encrypted message
def verify_message(encrypted_message):
    '''This function is to verify the message'''
    message, digest = encrypted_message.split("::")
    expected_digest = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return digest == expected_digest

# Function to receive messages from the server and print them to the chat window
def receive_messages():
    '''This function is to receive and decrypt the message'''
    while True:
        encrypted_message = client_socket.recv(1024).decode()
        if not encrypted_message:
            break
        if verify_message(encrypted_message):
            message = encrypted_message.split("::")[0]
            messages_listbox.insert(tk.END, f'{message}')

# Function to send messages to the server
def send_message():
    '''This function is to send message to the server'''
    message = input_text.get()
    if message:
        encrypted_message = encrypt_message(f"{name}: {message}")
        client_socket.send(encrypted_message.encode())
        input_text.set('')
        # Insert the message in the messages listbox
        messages_listbox.insert(tk.END, f'{name}: {message}')

# Connect to the server
ip_address = '192.168.2.56' #Change IP address to the server's IP.
port = 8888
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((ip_address, port))

name = input("Type in your name: ")

# Create the chat interface
root = tk.Tk()
root.title('Chat')

# Create a listbox to display the messages
messages_listbox = tk.Listbox(root, width=50, height=20)
messages_listbox.pack(side=tk.LEFT, padx=10, pady=10)

# Create a scrollbar for the listbox
scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Attach the scrollbar to the listbox
messages_listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=messages_listbox.yview)

# Create a frame for the input field and button
input_frame = tk.Frame(root)
input_frame.pack(side=tk.BOTTOM, padx=10, pady=10)

# Create a variable to store the text in the input field
input_text = tk.StringVar()

# Create an input field and attach it to the variable
input_entry = tk.Entry(input_frame, width=50, textvariable=input_text)
input_entry.pack(side=tk.LEFT)

# Create a button to send the message
send_button = tk.Button(input_frame, text='Send', command=send_message)
send_button.pack(side=tk.RIGHT)

# Start a separate thread to receive messages from the server
threading.Thread(target=receive_messages).start()

# Start the main loop
root.mainloop()

