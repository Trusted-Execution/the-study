#!/usr/bin/python
import os
import time
import platform
from isElf import isElfFile
from isMZ import isMzFile
import pefile
from elftools.elf.elffile import ELFFile

countElf = 0
countElfSize = 0
count100Elf = 0
countPE = 0
countPeSize = 0
count100Pe = 0
elfSectionSizeData = {}
peSectionSizeData = {}
elfFileInfo = [];
peFileInfo = []
start_time = time.time()

current_system = platform.system()

# Specify filepath(s) to run on based on OS
if current_system == 'Linux':
    home_directory = r"/"
    subdirectories = ("/home", "/usr", "/etc", "/opt", "/root")
elif current_system == 'Windows':
    home_directory = r"C:\System64"
    subdirectories = ("")
else:
    print("You are running this script on an unsupported system! Please try again on a Linux or Windows system.")
    exit()

for subdir, dirs, files in os.walk(home_directory):
    if subdir.startswith(subdirectories):
        for file in files:
            try:
                filepath = os.path.join(subdir, file)
                filename = os.path.basename(filepath)
                _, extension = os.path.splitext(filename)
                if os.path.islink(filepath) == False:
                    if isElfFile(filepath):
                        countElf += 1
                        print("\nELF file:", filepath, "\n----------------------------")
                        with open(filepath, 'rb') as f:
                            elf = ELFFile(f)
                            for segment in elf.iter_segments():
                                print(segment)
                    elif isMzFile(filepath, 0):
                        countPE += 1
                        print("\nPE file:", filepath, "\n----------------------------")
                        pe = pefile.PE(filepath)
                        for section in pe.sections:
                            print(section)
            except Exception as e:
                print(f"Error accessing file '{filepath}': {e}")

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"\nTotal PE files: {countPE}")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
