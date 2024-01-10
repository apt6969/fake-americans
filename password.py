import pyperclip
import random
import secrets
import string
import bcrypt
import os
import sys
import argparse
import pickle
# from Crypto.Cipher import Blowfish
# from Crypto.Random import get_random_bytes
from struct import pack
import bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def encrypt(key, plaintext):
    # Pad the plaintext to be a multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Create a Cipher object with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt(key, ciphertext):
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a Cipher object with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def pokimane_symmetric(username):
    # Your symmetric key
    key = b'pokimane' # Ensure this is 16, 24, or 32 bytes long for AES

    # Ensure key is the right length (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256)
    key = key.ljust(32, b'\0')
    # Encrypt and decrypt
    raw_text = gen_pw()
    print(raw_text)

    plaintext = raw_text.encode('utf-8')

    ciphertext = encrypt(key, plaintext)
    decrypted_text = decrypt(key, ciphertext)

    print("Original:", plaintext)
    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypted_text)

    with open("my_symettric_key.pickle", "wb") as f:
        pickle.dump({}, f)
    with open("my_symettric_key.pickle", "rb") as f:
        my_symettric_key = pickle.load(f)
    my_symettric_key[username] = gen_pw()
    with open("my_symettric_key.pickle", "wb") as f:
        pickle.dump(my_symettric_key, f)   
    return my_symettric_key[username]

# def Blowfish_Unsecure_Maybe_PokimaneSucks(encrypt_or_decrypt):
#     # Key should be between 4 and 56 bytes long
#     key = b'PokimaneSucks'

#     cipher = Blowfish.new(key, Blowfish.MODE_CBC)

#     # Blowfish requires block size to be 8 bytes
#     bs = Blowfish.block_size
#     plaintext = b'Pokimane'
#     plen = bs - len(plaintext) % bs
#     padding = [plen]*plen
#     padding = pack('b'*plen, *padding)

#     if encrypt_or_decrypt:
#         msg = cipher.iv + cipher.encrypt(plaintext + bytes(padding))
#         #return msg
#         with open("test.bin", "wb") as f:
#             f.write(msg)

#     else:
#     # Decryption
#         iv = msg[:bs]
#         ciphertext = msg[bs:]
#         cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
#         decrypted = cipher.decrypt(ciphertext)

#         last_byte = decrypted[-1]
#         decrypted = decrypted[:-last_byte]

#         return decrypted

# def TestBlowfish(Some_Boolean):
#     print(Blowfish_Unsecure_Maybe_PokimaneSucks(True))
#     print(Blowfish_Unsecure_Maybe_PokimaneSucks(False))

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

def gen_pw():
    return generate_password(random.randrange(15, 18))

def store_raw_pw(username):
    random_pw = generate_password(random.randrange(15, 18))
    with open("my_raw_passwords.pickle", "wb") as f:
        pickle.dump({}, f)
    
    with open("my_raw_passwords.pickle", "rb") as f:
        raw_pw_dict = pickle.load(f)
    
    raw_pw_dict[username] = random_pw

    with open("my_raw_passwords.pickle", "wb") as f:
        pickle.dump(raw_pw_dict, f)

def get_pw(username):
    with open("my_raw_passwords.pickle", "rb") as f:
        raw_pw_dict = pickle.load(f)
    return raw_pw_dict[username]
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Usage of random_pw.py')
    parser.add_argument('--C', action='store_true', help='Generate random pw to copy')
    parser.add_argument('--G', type=str, help='Generate pw for your username')
    parser.add_argument('--username', type=str, help='Get pw from your username')
    args = parser.parse_args()
    copy_bool = args.C
    g_username = args.G
    username_string = args.username

    # TestBlowfish(True)
    pokimane_symmetric('pokimane')
    if g_username:
        pw = gen_pw()
        hashed_pw = hash_password(pw)
        store_password(g_username, hashed_pw, "my_passwords.txt")
        with open("my_raw_passwords.pickle", "wb") as f:
            empty_dict = {}
            pickle.dump(empty_dict, f)
        with open("my_raw_passwords.pickle", "rb") as f:
            raw_pw_dict = pickle.load(f)
        raw_pw_dict[g_username] = pw
        with open("my_raw_passwords.pickle", "wb") as f:
            pickle.dump(raw_pw_dict, f)
    elif username_string:
        raw_pw = get_pw(username_string)
        pyperclip.copy(f'{raw_pw}')
    else:
        copy_pw()