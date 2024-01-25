#!/usr/bin/python
import os
from isElf import is_elf_file


count = 0
for subdir, dirs, files in os.walk("/"):
    if subdir.startswith(("/usr", "/etc", "/opt", "/root")):
        for file in files:
            filepath = os.path.join(subdir, file)
            if is_elf_file(filepath):
                count += 1

print(f'Total elf files: {count}')

