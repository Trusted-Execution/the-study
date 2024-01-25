#!/usr/bin/python
import pefile

def mzSectionSizes(file_path):
    # Parse file with pefile library
    pe = pefile.PE(file_path)
    print("{:<10}{:<10}{:<10}".format("Section", "Virtual", "Raw"))
    print("-" * 30)
    for section in pe.sections:
        print("{:<10}{:<10}{:<10}".format(section.Name.decode('utf-8').rstrip('\x00'), section.Misc_VirtualSize, section.SizeOfRawData))