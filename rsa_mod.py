import random
import time
import math
from sympy import isprime
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode

class RSA:
    def _init_(self):
        self.bitlength = 1024
        self.r = random.SystemRandom()
        self.generate_primes()
        self.generate_key_pairs()

    def generate_primes(self):
        self.p = self.random_prime()
        print(f"The value of prime number p is: {self.p}")
        if isprime(self.p):
            print("The big integer p is a probable prime number")
        else:
            print("The big integer p is not a prime number...please execute again")
        print(f"The length of p is - {len(str(self.p))}")

        self.q = self.random_prime()
        print(f"The value of prime number q is: {self.q}")
        if isprime(self.q):
            print("The big integer q is a probable prime number")
        else:
            print("The big integer q is not a prime number...please execute again")
        print(f"The length of q is - {len(str(self.q))}")

    def random_prime(self):
        while True:
            num = self.r.getrandbits(self.bitlength)
            if isprime(num):
                return num

    def generate_key_pairs(self):
        self.n = self.p * self.q
        print(f"The value of prime number n is: {self.n}")
        print(f"The length of n is - {len(str(self.n))}")

        phi = (self.p - 1) * (self.q - 1)
        e = self.random_coprime(phi)

        while math.gcd(phi, e) > 1 and e < phi:
            e += 1
        self.e = e
        self.d = pow(e, -1, phi)  # Calculate the modular multiplicative inverse of e modulo phi
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.e, self.d)
        
    def random_coprime(self, phi):
        while True:
            num = self.r.randint(2, phi - 1)
            if math.gcd(phi, num) == 1:
                return num

    def encrypt(self, plaintext):
        rsa_key = CryptoRSA.construct((self.n, self.e))
        cipher = PKCS1_OAEP.new(rsa_key)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        rsa_key = CryptoRSA.construct((self.n, self.e, self.d))
        cipher = PKCS1_OAEP.new(rsa_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

def print_keys(self):
    print("\n------------ Public Key --------------")
    print("n:", self.public_key[0])
    print("e:", self.public_key[1])
    
def main():
    start = int(time.time() * 1000)
    teststring = input("Enter the text to be encrypted: ")
    print("------------ Generating very large prime numbers of given bitlength --------------")
    rsa = RSA()

    print("\n------------ Encrypting text --------------")
    encrypted = rsa.encrypt(teststring.encode())
    print("Encrypted String:", b64encode(encrypted).decode())

    print("\n------------ Decrypting text --------------")
    decrypted = rsa.decrypt(encrypted)
    print("Decrypted String:", decrypted.decode())

    if teststring == decrypted.decode():
        end = int(time.time() * 1000)
        print(f"\nx-------------- RSA Algorithm is successful ------------x")
        print(f"The run time for bitlength {rsa.bitlength} is {(end - start) / 1000:.2f} seconds")
    else:
        print(f"\nx-------------- RSA Algorithm is unsuccessful ------------x")

if __name__ == "__main__":
    main()