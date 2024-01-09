def view_binary_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            while True:
                byte = file.read(1)
                if not byte:
                    break
                print(byte.hex(), end=' ')
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    file_path = "test.bin"  # Replace with the path to your binary file
    view_binary_file(file_path)