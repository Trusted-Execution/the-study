#!/usr/bin/python
import os
import time
import platform
import math
import argparse
import sys
 
# setting path
sys.path.append('../utils')

from utils.isElf import isElfFile
from utils.isMZ import isMzFile
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_flags
from decodeCharacteristics import decodeChars

countElf = 0
countElfSize = 0
countPE = 0
countPeSize = 0
count100 = 0
elfSectionSizeData = {}
peSectionSizeData = {}
elfFileInfo = []
peFileInfo = []
start_time = time.time()

current_system = platform.system()

def parse_arguments():
    parser = argparse.ArgumentParser(description='File Segment Analysis Script')
    parser.add_argument('--debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()
args = parse_arguments()
debug_mode = args.debug

# Specify filepath(s) to run on based on OS
if current_system == 'Linux':
    home_directory = r"/"
    subdirectories = ("/home", "/usr", "/etc", "/opt", "/root")
elif current_system == 'Windows':
    home_directory = r"C:\\"
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
                    count100 += 1
                    if (count100 == 100) and debug_mode == 0:
                        print(".", end=" ", flush=True)
                        count100 = 0
                    if isElfFile(filepath):
                        countElf += 1
                        if debug_mode == 1:
                            print("\nELF file:", filepath, "\n----------------------------")
                        with open(filepath, 'rb') as f:
                            elf = ELFFile(f)
                            for segment in elf.iter_segments():
                                if debug_mode == 1:
                                    print("Segment type:", segment['p_type'])
                                    print("Permissions:", describe_p_flags(segment['p_flags']))
                                    print("Virtual address:", hex(segment['p_vaddr']))
                                    print("Physical address:", hex(segment['p_paddr']))
                                    print("File offset:", hex(segment['p_offset']))
                                    print("Size in memory:", segment['p_memsz'])
                                    print("Size in file:", segment['p_filesz'])
                                    print()

                                name = segment['p_type']
                                flags = describe_p_flags(segment['p_flags'])
                                key = (name, flags)
                                sizeInMem = segment['p_memsz']
                                sizeInFile = segment['p_filesz']

                                if key not in elfSectionSizeData:
                                    elfSectionSizeData[key] = {
                                        "count": 0,
                                        "sizesInMem": [],
                                        "minInMem": float('inf'),
                                        "maxInMem": float('-inf'),
                                        "sumInMem": 0,
                                        "sizesInFile": [],
                                        "minInFile": float('inf'),
                                        "maxInFile": float('-inf'),
                                        "sumInFile": 0,
                                    }
                            
                                elfSectionSizeData[key]["count"] += 1
                                elfSectionSizeData[key]["sizesInMem"].append(sizeInMem)
                                elfSectionSizeData[key]["minInMem"] = min(elfSectionSizeData[key]["minInMem"], sizeInMem)
                                elfSectionSizeData[key]["maxInMem"] = max(elfSectionSizeData[key]["maxInMem"], sizeInMem)
                                elfSectionSizeData[key]["sumInMem"] += sizeInMem

                                elfSectionSizeData[key]["sizesInFile"].append(sizeInFile)
                                elfSectionSizeData[key]["minInFile"] = min(elfSectionSizeData[key]["minInFile"], sizeInFile)
                                elfSectionSizeData[key]["maxInFile"] = max(elfSectionSizeData[key]["maxInFile"], sizeInFile)
                                elfSectionSizeData[key]["sumInFile"] += sizeInFile

                    elif isMzFile(filepath, 0):
                        countPE += 1
                        if debug_mode == 1:
                            print("\nPE file:", filepath, "\n----------------------------")
                        pe = pefile.PE(filepath)
                        for section in pe.sections:
                            name = section.Name.decode().rstrip('\x00')  # Clean up section name
                            characteristics = section.Characteristics
                            size_of_raw_data = section.SizeOfRawData
                            key = (name, characteristics)
                            if debug_mode == 1:
                                print(section)

                            if key not in peSectionSizeData:
                                peSectionSizeData[key] = {
                                    "count": 0,
                                    "sizes": [],
                                    "min": float('inf'),
                                    "max": float('-inf'),
                                    "sum": 0,
                                }
                            
                            peSectionSizeData[key]["count"] += 1
                            peSectionSizeData[key]["sizes"].append(size_of_raw_data)
                            peSectionSizeData[key]["min"] = min(peSectionSizeData[key]["min"], size_of_raw_data)
                            peSectionSizeData[key]["max"] = max(peSectionSizeData[key]["max"], size_of_raw_data)
                            peSectionSizeData[key]["sum"] += size_of_raw_data
            except Exception as e:
                print(f"Error accessing file '{filepath}': {e}")

print("\nPE File Segment Analysis:\n")
print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format("Segment Name", "Characteristics", "Avg Size of Raw Data (bytes)", "Max", "Min", "STD", "Count"))
for key, data in peSectionSizeData.items():
    name = key[0]
    characteristics = key[1]
    count = data["count"]
    avg = data["sum"] / count
    variance = sum((x - avg) ** 2 for x in data["sizes"]) / count
    std_dev = math.sqrt(variance)
    print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format(name, decodeChars(characteristics), round(avg, 2), data['max'], data['min'], round(std_dev, 2), count))

print("\nELF File Segment Analysis (Sizes in Memory):\n")
print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format("Segment Name", "Characteristics", "Avg Size (bytes)", "Max", "Min", "STD", "Count"))
for key, data in elfSectionSizeData.items():
    name = key[0]
    flags = key[1]
    count = data["count"]
    avg = data["sumInMem"] / count
    variance = sum((x - avg) ** 2 for x in data["sizesInMem"]) / count
    std_dev = math.sqrt(variance)
    print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format(name, flags, round(avg, 2), data['maxInMem'], data['minInMem'], round(std_dev, 2), count))

print("\nELF File Segment Analysis (Sizes in File):\n")
print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format("Segment Name", "Characteristics", "Avg Size (bytes)", "Max", "Min", "STD", "Count"))
for key, data in elfSectionSizeData.items():
    name = key[0]
    flags = key[1]
    count = data["count"]
    avg = data["sumInFile"] / count
    variance = sum((x - avg) ** 2 for x in data["sizesInFile"]) / count
    std_dev = math.sqrt(variance)
    print("{:<20} {:<20} {:<30} {:<10} {:<15} {:<20} {:<8}".format(name, flags, round(avg, 2), data['maxInFile'], data['minInFile'], round(std_dev, 2), count))


end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"\nTotal PE files: {countPE}")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
