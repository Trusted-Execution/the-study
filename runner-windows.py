#!/usr/bin/python
import os
from isMZ import isMzFile
from fileSize import getSize
from mzSectionSize import mzSectionSizes

countMz = 0
countMzSize = 0
for subdir, dirs, files in os.walk(r"C:\Users\nakam\Downloads"):   # Change to your own local test directory
    for file in files:
        filepath = os.path.join(subdir, file)
        if os.path.islink(filepath) == False:
            if isMzFile(filepath):
                countMzSize += getSize(filepath)
                countMz += 1
                # Print size of each section
                mzSectionSizes(filepath)
                print("-" * 50)

print(f"Total MZ files: {countMz}")
print(f"Total MZ file size: {countMzSize} bytes")