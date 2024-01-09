import pyperclip
import random
import secrets
import string
#import brcypt
import os
import sys
import argparse
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from struct import pack

def Blowfish_Unsecure_Maybe_PokimaneSucks(encrypt_or_decrypt):
    # Key should be between 4 and 56 bytes long
    key = b'PokimaneSucks'

    cipher = Blowfish.new(key, Blowfish.MODE_CBC)

    # Blowfish requires block size to be 8 bytes
    bs = Blowfish.block_size
    plaintext = b'Pokimane'
    plen = bs - len(plaintext) % bs
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)

    if encrypt_or_decrypt:
        msg = cipher.iv + cipher.encrypt(plaintext + bytes(padding))
        #return msg
        with open("test.bin", "wb") as f:
            f.write(msg)

    else:
    # Decryption
        iv = msg[:bs]
        ciphertext = msg[bs:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        last_byte = decrypted[-1]
        decrypted = decrypted[:-last_byte]

        return decrypted

def TestBlowfish(Some_Boolean):
    print(Blowfish_Unsecure_Maybe_PokimaneSucks(True))
    print(Blowfish_Unsecure_Maybe_PokimaneSucks(False))

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def store_password(username, hashed_password, filename="my_passwords.txt"):
    # Store the hashed password in a file
    with open(filename, "a") as file:
        file.write(f"{username}:{hashed_password.decode()}\n")

def verify_password(username, password, filename="my_passwords.txt"):
    # Verify the password
    with open(filename, "r") as file:
        for line in file:
            stored_username, stored_hash = line.strip().split(":")
            if stored_username == username:
                return bcrypt.checkpw(password.encode(), stored_hash.encode())
    return False

def hash_password(password):
    # Hash a password with a randomly-generated salt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def copy_pw():
    random_pw = generate_password(random.randrange(15, 18))
    pyperclip.copy(f'{random_pw}')

def get_pw(username):
    return verify_password(sys.argv[1])

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Usage of random_pw.py')
    # parser.add_argument('--C', action='store_true', help='Generate random pw to copy')
    # parser.add_argument('--username', type=str, help='Get pw from your username')
    # args = parser.parse_args()
    # copy_bool = args.C
    # username_string = parser.username

    TestBlowfish(True)

    # if username_string:
    #     get_pw(username_string)
    # else:
    #     copy_pw()