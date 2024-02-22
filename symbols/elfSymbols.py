#!/usr/bin/python
from elftools.elf.elffile import ELFFile

def findSymbols(file_path):
    symbols = {}
    try:
        with open(file_path, 'rb') as file:
            elf_file = ELFFile(file)
            for section in elf_file.iter_sections():
                if section.name == '.symtab':
                    for symbol in section.iter_symbols():
                        name = symbol.name
                        size = symbol.entry.st_size
                        symbol_type = symbol.entry.st_info.type
                        symbols[name] = {
                                'Size': size,
                                'Type': symbol_type,
                                }
    except Exception as e:
        print(f"Error reading ELF file {file_path}: {e}")
        return None
    return symbols
