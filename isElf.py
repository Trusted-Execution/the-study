#!/usr/bin/python

def isElfFile(file_path):
    try:
        with open(file_path, 'rb') as file:
            elf_signature = file.read(4)
            if elf_signature == b'\x7fELF':
                print(f"{file_path} is a 7fELF file")
                return True
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

