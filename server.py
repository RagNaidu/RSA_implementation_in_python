import socket
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP

class ServerRSA:
    def __init__(self):
        self.bitlength = 1024
        self.private_key = None
        self.public_key = None
        self.rsa_keygen()

    def rsa_keygen(self):
        rsa_key = CryptoRSA.generate(self.bitlength)
        self.private_key = rsa_key
        self.public_key = rsa_key.publickey()

def server_program():
    host = socket.gethostname()
    port = 5004
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))

    server_rsa = ServerRSA()
    conn.send(server_rsa.public_key.export_key())  # Send the server's public key to the client

    client_public_key_str = conn.recv(4096)
    client_rsa_key = CryptoRSA.import_key(client_public_key_str)

    while True:
        message = conn.recv(4096)
        if not message:
            break

        cipher = PKCS1_OAEP.new(server_rsa.private_key)
        print(message)
        decrypted_message = cipher.decrypt(message)
        print("Received and Decrypted message from client: " + decrypted_message.decode())

        # Process the data (if needed)
        response = input("Enter a response to send to the client: ")
        cipher = PKCS1_OAEP.new(client_rsa_key)
        encrypted_response = cipher.encrypt(response.encode())
        
        conn.send(encrypted_response)

    conn.close()

if __name__ == '__main__':
    server_program()
