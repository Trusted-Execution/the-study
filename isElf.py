#!/usr/bin/python

def isElfFile(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read the first 4 bytes of the file
            elf_signature = file.read(4)
            # Check if it has the magic
            if elf_signature == b'\x7fELF':
                print(f"{file_path} is a 7fELF file")
                return True
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

