#!/usr/bin/python

def is_elf_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            elf_signature = file.read(4)
            return elf_signature == b'\x7fELF'
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

