#!/usr/bin/python

# Shortens file path name if too long
def truncate(file_path, max_length=40):
    if len(file_path) > max_length:
        return "..." + file_path[-(max_length - 3):]
    else:
        return file_path

def isMzFile(file_path):
    try:
        with open(file_path, 'rb') as file:
            mz_signature = file.read(2)
            if mz_signature == b'MZ':
                #name = truncate(file_path)
                print(f"{file_path} is a MZ file")
                return True
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

