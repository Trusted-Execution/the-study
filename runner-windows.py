#!/usr/bin/python
import os
from isMZ import isMzFile
from fileSize import getSize

countMz = 0
countMzSize = 0
for subdir, dirs, files in os.walk("C:\\Users\\b135c\\Downloads\\test"):
    for file in files:
        filepath = os.path.join(subdir, file)
        if os.path.islink(filepath) == False:
            if isMzFile(filepath):
                countMzSize += getSize(filepath)
                countMz += 1

print(f"Total MZ files: {countMz}")
print(f"Total MZ file size: {countMzSize}")