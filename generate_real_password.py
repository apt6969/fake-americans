import random
import string

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    pw = print(generate_password(random.randint(17, 20)))
    return pw

if __name__ == '__main__':
    main()