#!/usr/bin/python
import os
from isElf import isElfFile
from fileSize import getSize

countElf = 0
countElfSize = 0
for subdir, dirs, files in os.walk("/"):
    if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):
        for file in files:
            filepath = os.path.join(subdir, file)
            if os.path.islink(filepath) == False:
                if isElfFile(filepath):
                    countElfSize += getSize(filepath)
                    countElf += 1


print(f"Total elf files: {countElf}")
print(f"Total elf file size: {countElfSize}")