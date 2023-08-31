import csv
import random

def generate_names(number_of_names=1):
    surnames_capitalized = []
    with open('2010-census-surnames-appearing-over-100-times.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header if needed
        for row in reader:
            if row[0] != '' and row[0] != 'SURNAME' and row[0] != 'Source: U.S. Census Bureau, 2010 Census.' and row[0] != 'Note: Fields suppressed for confidentiality are assigned the value (S).':
                surnames_capitalized .append(row[0])  # Add the first column element of each row

    surnames_normal = [surname.lower().title() for surname in surnames_capitalized]
    top_1000_first_names = []

    with open('2010-census-top-1000-first-names.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header if needed
        for row in reader:
            if row[0] != '' and row[0] != 'SURNAME' and row[0] != 'Source: U.S. Census Bureau, 2010 Census.' and row[0] != 'Note: Fields suppressed for confidentiality are assigned the value (S).':
                top_1000_first_names.append(row[0])  # Add the first column element of each row

    first_names_normal = [fn.lower().title() for fn in top_1000_first_names]
    random_first = random.choice(first_names_normal)
    random_surname = random.choice(surnames_normal)
    print(random_first, random_surname)
    return(random_first, random_surname)

def main():
    generate_names()

if __name__ == '__main__': 
    main()