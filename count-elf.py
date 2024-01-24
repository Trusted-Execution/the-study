#!/usr/bin/python

import os

def is_elf_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            elf_signature = file.read(4)
            return elf_signature == b'\x7fELF'
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

def count_elf_files():
    count = 0
    for subdir, dirs, files in os.walk("/usr/bin/"):
        for file in files:
           filepath = os.path.join(subdir, file)
           if is_elf_file(filepath):
                count += 1
    return count


output = count_elf_files()
print(f'Total files: {output}')

