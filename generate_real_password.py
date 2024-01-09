import random
import string
import secrets

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def main():
    pw = print(generate_password(random.randint(17, 20)))
    return pw

if __name__ == '__main__':
    main()