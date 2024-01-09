import pyperclip
import random
import secrets
import string
#import brcypt
# import os
# import sys
# import argparse

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

# def store_password(username, hashed_password, filename="my_passwords.txt"):
#     # Store the hashed password in a file
#     with open(filename, "a") as file:
#         file.write(f"{username}:{hashed_password.decode()}\n")

# def verify_password(username, password, filename="my_passwords.txt"):
#     # Verify the password
#     with open(filename, "r") as file:
#         for line in file:
#             stored_username, stored_hash = line.strip().split(":")
#             if stored_username == username:
#                 return bcrypt.checkpw(password.encode(), stored_hash.encode())
#     return False

# def hash_password(password):
#     # Hash a password with a randomly-generated salt
#     return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def copy_pw():
    random_pw = generate_password(random.randrange(15, 18))
    pyperclip.copy(f'{random_pw}')

# def get_pw(username):
#     return verify_password(sys.argv[1])

if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Usage of random_pw.py')
    # parser.add_argument('--C', action='store_true', help='Generate random pw to copy')
    # parser.add_argument('--username', type=str, help='Get pw from your username')
    # args = parser.parse_args()
    # copy_bool = args.C
    # username_string = parser.username

    # if username_string:
    #     get_pw(username_string)
    # else:
    copy_pw()