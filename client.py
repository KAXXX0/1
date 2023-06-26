import socket
import subprocess
import os
# Use subprocess to execute the pip command with sudo
subprocess.run(['sudo', 'pip', 'install', 'pycryptodome'])
os.system('pip install pycryptodome')
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt a message using AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt a message using AES
def decrypt_message(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted_message.decode()

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
server_address = ('localhost', 12345)

# Connect to the server
client_socket.connect(server_address)
print('Connected to server:', server_address)

# Get the shared key from the user
key = input('Enter the shared key: ').encode()

# Pad or truncate the key to the correct length
key = key[:AES.block_size]  # Truncate if longer
key = key.ljust(AES.block_size, b'\0')  # Pad with zeros if shorter

# Send and receive messages
while True:
    # Send data to the server
    message = input('Enter your message: ')
    encrypted_message = encrypt_message(message, key)
    client_socket.sendall(encrypted_message)

    # Receive a response from the server
    encrypted_response = client_socket.recv(1024)
    response = decrypt_message(encrypted_response, key)
    print('Response:', response)

# Close the client socket
client_socket.close()