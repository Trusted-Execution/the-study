from elftools.elf.elffile import ELFFile

def sectionSizes(file_path):
    sectionSizes = {}
    try:
        with open(file_path, 'rb') as file:
            # Open file as an elf file
            elf_file = ELFFile(file)

            print(f"Section Sizes in ELF File: {file_path}\n")
            
            # Go through the sections
            for section in elf_file.iter_sections():
                # Print section name and size
                print(f"Section Name: {section.name}, Size: {section['sh_size']} bytes")
                sectionSizes[section.name] = section['sh_size']

    except Exception as e:
        print(f"Error reading ELF file {file_path}: {e}")

    return sectionSizes
