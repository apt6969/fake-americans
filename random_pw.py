import pyperclip
import random
import secrets
import string

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

random_pw = generate_password(random.randrange(15, 18))
pyperclip.copy(f'{random_pw}')
