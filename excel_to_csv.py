import pandas as pd
import sys

def main():
    read_file = pd.read_excel (sys.argv[1])
    read_file.to_csv (sys.argv[2], 
                    index = None,
                    header=True)

if __name__ == '__main__':
    main()