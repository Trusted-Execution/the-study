import pefile

def findMzSymbols(file_path, debug_mode):
    try:
        pe = pefile.PE(file_path)
        export_dir_rva = getattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']], 'VirtualAddress', None)

        if export_dir_rva:
            export_section = None

            # Find the section containing the export directory
            for section in pe.sections:
                if section.VirtualAddress <= export_dir_rva < (section.VirtualAddress + section.Misc_VirtualSize):
                    export_section = section
                    break
            if export_section:
                export_symbols = {}
                for idx, entry in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols):
                    symbol_name = entry.name.decode('utf-8') if entry.name else None
                    symbol_size = 0

                    # Calculate symbol size
                    if idx < len(pe.DIRECTORY_ENTRY_EXPORT.symbols) - 1:
                        next_entry = pe.DIRECTORY_ENTRY_EXPORT.symbols[idx + 1]
                        symbol_size = abs(next_entry.address - entry.address)
                    else:
                        # For the last symbol, calculate size from the end of the section
                        section_end = export_section.VirtualAddress + export_section.Misc_VirtualSize
                        symbol_size = abs(section_end - entry.address)

                    export_symbols[symbol_name] = {
                        'Size': symbol_size
                    }
            return export_symbols
        else:
            if debug_mode:
                print(f"No export directory found in {file_path}")
    except Exception as e:
        if debug_mode:
            print(f"Error reading PE file {file_path}: {e}")
    return None