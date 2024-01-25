#!/usr/bin/python

def isMzFile(file_path):
    try:
        with open(file_path, 'rb') as file:
            mz_signature = file.read(2)
            if mz_signature == b'MZ':
                print(f"{file_path} is a MZ file")
                return True
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

