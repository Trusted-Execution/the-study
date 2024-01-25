#!/usr/bin/python
import os
from isMZ import isMzFile
from fileSize import getSize
from mzSectionSize import mzSectionSizes

countMz = 0
countMzSize = 0
totalSizes = {}

for subdir, dirs, files in os.walk(r"C:\Users\nakam\Downloads"):   # Change to your own local test directory
    for file in files:
        filepath = os.path.join(subdir, file)
        if os.path.islink(filepath) == False:
            if isMzFile(filepath):
                countMzSize += getSize(filepath)
                countMz += 1
                # Print size of each section
                sectionSizes = mzSectionSizes(filepath)
                print("-" * 50)

                # Sum the sizes of each section
                for name, size in sectionSizes.items():
                    if name in totalSizes:
                        totalSizes[name] += size
                    else:
                        totalSizes[name] = size

print("\nAverage Section Sizes (based on raw size) across MZ Files:\n")
print("{:<25} {:<20}".format("Section Name", "Average Size (bytes)"))
for name, size in totalSizes.items():
    average = size / countMz
    print("{:<25} {:<20}".format(name, round(average, 2)))

print(f"\nTotal MZ files: {countMz}")
print(f"Total MZ file size: {countMzSize} bytes\n")