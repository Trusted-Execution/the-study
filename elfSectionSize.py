from elftools.elf.elffile import ELFFile

def sectionSizes(file_path):
    sectionSizes = {}
    try:
        with open(file_path, 'rb') as file:
            # Open file as an elf file
            elf_file = ELFFile(file)

            #print("{:<20}{:<20}".format("Section", "Size"))
            #print("-" * 28)
            
            # Go through the sections
            for section in elf_file.iter_sections():
                # Print section name and size
                #print("{:<20}{:<20}".format(section.name, section['sh_size']))
                sectionSizes[section.name] = section['sh_size']

    except Exception as e:
        print(f"Error reading ELF file {file_path}: {e}")

    return sectionSizes
