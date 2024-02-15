#!/usr/bin/python

# Shortens file path name if too long
def truncate(file_path, max_length=40):
    if len(file_path) > max_length:
        return "..." + file_path[-(max_length - 3):]
    else:
        return file_path

def isMzFile(file_path, debug_mode = 0):
    try:
        with open(file_path, 'rb') as file:
            mz_signature = file.read(2)
            if mz_signature == b'MZ':
                file.seek(60)
                pe_offset = int.from_bytes(file.read(2), 'little')
                file.seek(pe_offset)
                pe_signature = file.read(4)
                if pe_signature == b'PE\x00\x00':
                    if debug_mode:
                        print(f"{truncate(file_path)} is a PE file")
                    return True
                else:
                    if debug_mode:
                        print(f"{truncate(file_path)} is an MZ file but not a PE file")
                    return False
            else:
                if debug_mode:
                    print(f"{truncate(file_path)} is not an MZ file")
                return False
    except Exception as e:
        if debug_mode:
            print(f"Error checking file {file_path}: {e}")
        return False

