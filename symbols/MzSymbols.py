import pefile

def findSymbols(file_path, debug_mode):
    try:
        pe = pefile.PE(file_path)

        # Check if the PE file has an export directory
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            export_symbols = {}
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                symbol_name = entry.name.decode('utf-8') if entry.name else None
                export_symbols[symbol_name] = {
                    'Ordinal': entry.ordinal,
                    'Address': entry.address,
                }
            return export_symbols
        else:
            if debug_mode:
                print(f"No export directory found in {file_path}")
    except Exception as e:
        if debug_mode:
            print(f"Error reading PE file {file_path}: {e}")
    return None