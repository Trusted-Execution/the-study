#!/usr/bin/python

# Shortens file path name if too long
def truncate(file_path, max_length=40):
    if len(file_path) > max_length:
        return "..." + file_path[-(max_length - 3):]
    else:
        return file_path

def isElfFile(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read the first 4 bytes of the file
            elf_signature = file.read(4)
            # Check if it has the magic
            if elf_signature == b'\x7fELF':
                #name = truncate(file_path)
                print(f"{file_path} is a 7fELF file")
                return True
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

