#!/usr/bin/python
import os
import struct
from isElf import isElfFile
from fileSize import getSize
from elfSectionSize import sectionSizes
import statistics

countElf = 0
countElfSize = 0
sectionSizeData = {}

for subdir, dirs, files in os.walk("/usr/bin"):
   # if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):
        for file in files:
            file_path = os.path.join(subdir, file)
            if os.path.islink(file_path) == False:
                if isElfFile(file_path):
                    countElfSize += getSize(file_path)
                    countElf += 1
                    tempSectionSizes = sectionSizes(file_path)
                    print("-" * 50)

                    for section_name, size in tempSectionSizes.items():
                        if section_name in sectionSizeData:
                            sectionSizeData[section_name].append(size)
                        else:
                            sectionSizeData[section_name] = [size]

# Print as table
print("\nAverage, Maximum, Minimum, and Standard Deviation of Section Sizes across ELF Files:\n")
print("{:<25} {:<20} {:<20} {:<20} {:<20}".format("Section Name", "Average Size (bytes)", "Maximum Size", "Minimum Size", "Standard Deviation"))
for section_name, sizes in sectionSizeData.items():
    average_size = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0

    print("{:<25} {:<20} {:<20} {:<20} {:<20}".format(section_name, round(average_size, 2), max_size, min_size, round(std, 2)))

print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
