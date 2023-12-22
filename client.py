import socket
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP

def client_program():
    host = socket.gethostname()
    port = 5004

    client_socket = socket.socket()
    client_socket.connect((host, port))

    rsa_key = CryptoRSA.generate(1024)  # Generate a new key pair for the client
    server_public_key_str = client_socket.recv(4096)
    server_public_key = CryptoRSA.import_key(server_public_key_str)

    client_socket.send(rsa_key.publickey().export_key())  # Send the client's public key to the server

    while True:
        message = input("Enter a message to send to the server: (to quit ctrl+c): ")

        cipher = PKCS1_OAEP.new(server_public_key)
        encrypted_message = cipher.encrypt(message.encode())
        client_socket.send(encrypted_message)

        response = client_socket.recv(4096)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_response = cipher.decrypt(response)

        # Print the encrypted response received from the server
        print("Encrypted response received from the server: " + repr(response))
        
        print("Received decrypted response from the server: " + decrypted_response.decode())

    client_socket.close()

if __name__ == '__main__':
    client_program()
