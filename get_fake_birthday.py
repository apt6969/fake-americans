import random

def generate_fake_birthday():
    birth_years = list(range(1969, 2003))
    birth_months = list(range(1, 13))
    birty_days = list(range(1, 29))
    by = random.choice(birth_years)
    bm = random.choice(birth_months)
    bd = random.choice(birty_days)
    print(by, bm, bd)
    return by, bm, bd

def main():
    generate_fake_birthday()

if __name__ == '__main__':
    main()