#!/usr/bin/python
import os
import struct
from isElf import isElfFile
from fileSize import getSize
from sectionSize import sectionSizes

countElf = 0
countElfSize = 0
totalSectionSizes = {}

for subdir, dirs, files in os.walk("/usr/bin"):
   # if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):
        for file in files:
            file_path = os.path.join(subdir, file)
            if os.path.islink(file_path) == False:
                if isElfFile(file_path):
                    countElfSize += getSize(file_path)
                    countElf += 1
                    tempSectionSizes = sectionSizes(file_path)

                    for section_name, size in tempSectionSizes.items():
                        if section_name in totalSectionSizes:
                            totalSectionSizes[section_name] += size
                        else:
                            totalSectionSizes[section_name] = size
# Print as table
print()
print("--------------------------------------------------")
print("\nAverage Section Sizes across ELF Files:\n")
print("{:<20} {:<20}".format("Section Name", "Average Size (bytes)"))
for section_name, total_size in totalSectionSizes.items():
    average_size = total_size / countElf
    print("{:<20} {:<20}".format(section_name, round(average_size, 2)))

print(f"Total elf files: {countElf}")
print(f"Total elf file size: {countElfSize}")
