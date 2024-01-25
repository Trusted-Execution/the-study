#!/usr/bin/python
import pefile

def mzSectionSizes(file_path):
    # Dictionary to hold section-size pairs
    sectionSizes = {}
    # Parse file with pefile library
    pe = pefile.PE(file_path, fast_load=True)
    print("{:<10}{:<10}{:<10}".format("Section", "Virtual", "Raw"))
    print("-" * 30)
    for section in pe.sections:
        sectionName = section.Name.decode('utf-8').rstrip('\x00')
        print("{:<10}{:<10}{:<10}".format(sectionName, section.Misc_VirtualSize, section.SizeOfRawData))
        # Store section and size in dictionary (using raw data for now)
        sectionSizes[sectionName] = section.SizeOfRawData

    return sectionSizes