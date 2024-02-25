#!/usr/bin/python
import os
import struct
import time
import statistics
import pandas as pd
import argparse
from datetime import datetime
from isElf import isElfFile
from isMZ import isMzFile
from fileSize import getSize
from elfSectionSize import elfSectionSizes
from mzSectionSize import mzSectionSizes

def parse_arguments():
    parser = argparse.ArgumentParser(description='Executable analysis tool for Windows and Linux')
    parser.add_argument('--system', required=True, choices=['linux', 'windows'], type=str, default='linux', help='Specify the operating system you are currently on')
    return parser.parse_args()

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

args = parse_arguments()

# Specify filepath to run on based on OS
if args.system == 'linux':
    home_directory = r"/"
    subdirectories = ("/home", "/usr", "/etc", "/opt", "/root")
elif args.system == 'windows':
    home_directory = r"C:\\"
    subdirectories = ("")

for subdir, dirs, files in os.walk(home_directory):
    if subdir.startswith(subdirectories):       # Comment out this line on Windows
        for file in files:
            try:
                filepath = os.path.join(subdir, file)
                filename = os.path.basename(filepath)
                _, extension = os.path.splitext(filename)
                if os.path.islink(filepath) == False:
                    if isElfFile(filepath):
                        countElfSize += getSize(filepath)
                        countElf += 1
                        count100Elf += 1
                        tempSectionSizes = elfSectionSizes(filepath)
                        # Print . every 100 ELF files
                        if (count100Elf == 100):
                            print(".", end=" ", flush=True)
                            count100Elf = 0
                        for name, size in tempSectionSizes.items():
                            if name in elfSectionSizeData:
                                elfSectionSizeData[name].append(size)
                            else:
                                elfSectionSizeData[name] = [size]
                            file_data = {
                                'File Path': filepath,
                                'File Name': filename,
                                'Extension': extension,
                                'Date Created': datetime.fromtimestamp(os.path.getctime(filepath)),
                                'File Size': getSize(filepath),
                                'Section Name': name,
                                'Section Size': size
                            }
                            elfFileInfo.append(file_data)
                    elif isMzFile(filepath, 0):
                        count100Pe += 1
                        countPeSize += getSize(filepath)
                        countPE += 1
                        # Print size of each section
                        sectionSizes = mzSectionSizes(filepath, 0)
                        # Print * every 100 PE files
                        if (count100Pe == 100):
                            print("*", end=" ", flush=True)
                            count100Pe = 0 
                        # Sum the sizes of each section
                        for name, size in sectionSizes.items():
                            if name in peSectionSizeData:
                                peSectionSizeData[name].append(size)
                            else:
                                peSectionSizeData[name] = [size]
                            file_data = {
                                'File Path': filepath,
                                'File Name': filename,
                                'Extension': extension,
                                'Date Created': datetime.fromtimestamp(os.path.getctime(filepath)),
                                'File Size': getSize(filepath),
                                'Section Name': name,
                                'Section Size': size
                            }
                            peFileInfo.append(file_data);
            except Exception as e:
                print(f"Error accessing file '{filepath}': {e}")

# Create Pandas dataframes
elf_df = pd.DataFrame(list(elfSectionSizeData.items()), columns=['Section', 'Size'])
pe_df = pd.DataFrame(list(peSectionSizeData.items()), columns=['Section', 'Size'])
elf_file_df = pd.DataFrame(elfFileInfo)
pe_file_df = pd.DataFrame(peFileInfo)

# Perform analysis on data
elf_df['Avg'] = elf_df['Size'].apply(lambda sizes: sum(sizes) / len(sizes))
elf_df['Max'] = elf_df['Size'].apply(max)
elf_df['Min'] = elf_df['Size'].apply(min)
elf_df['Std'] = elf_df['Size'].apply(lambda sizes: statistics.stdev(sizes) if len(sizes) >= 2 else 0.0)
elf_df['Count'] = elf_df['Size'].apply(len)

pe_df['Avg'] = pe_df['Size'].apply(lambda sizes: sum(sizes) / len(sizes))
pe_df['Max'] = pe_df['Size'].apply(max)
pe_df['Min'] = pe_df['Size'].apply(min)
pe_df['Std'] = pe_df['Size'].apply(lambda sizes: statistics.stdev(sizes) if len(sizes) >= 2 else 0.0)
pe_df['Count'] = pe_df['Size'].apply(len)

# Sort alphabetically based on section name
elf_df.sort_values('Section', inplace=True)
pe_df.sort_values('Section', inplace=True)

# Remove column with all the section sizes
elf_df = elf_df.drop('Size', axis=1)
pe_df = pe_df.drop('Size', axis=1)

# Generate results and store in correct folder based on system
if args.system == 'linux':
    elf_df.to_csv('results/linux/elf_section_analysis.csv', sep='\t', index=False)
    pe_df.to_csv('results/linux/pe_section_analysis.csv', sep='\t', index=False)
    elf_file_df.to_csv('results/linux/elf_files_with_sections.txt', sep='\t', index=False)
    pe_file_df.to_csv('results/linux/pe_files_with_sections.txt', sep='\t', index=False)
elif args.system == 'windows':
    elf_df.to_csv('results/windows/elf_section_analysis.csv', sep='\t', index=False)
    pe_df.to_csv('results/windows/pe_section_analysis.csv', sep='\t', index=False)
    elf_file_df.to_csv('results/windows/elf_files.txt', sep='\t', index=False)
    pe_file_df.to_csv('results/windows/pe_files.txt', sep='\t', index=False)

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
print(f"\nTotal PE files: {countPE}")
print(f"Total PE file size: {countPeSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
