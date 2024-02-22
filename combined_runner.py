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
    parser = argparse.ArgumentParser(description='PE File Analysis Script')
    parser.add_argument('-debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()

countElf = 0
countElfSize = 0
count100Elf = 0
countPE = 0
countPeSize = 0
count100Pe = 0
elfSectionSizeData = {}
peSectionSizeData = {}
elfFileInfo = []
peFileInfo = []
start_time = time.time()

args = parse_arguments()
debug_mode = args.debug

for subdir, dirs, files in os.walk(r"C:\\"):                 # Change to desired directory on system
    #if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):      # Comment out this line on Windows
        for file in files:
            filepath = os.path.join(subdir, file)
            filename = os.path.basename(filepath)
            _, extension = os.path.splitext(filename)
            # Generate information on individual files
            file_data = {
                'File Path': filepath,
                'File Name': filename,
                'Extension': extension,
                'Date Created': datetime.fromtimestamp(os.path.getctime(filepath)),
                'Size': getSize(filepath)
            }
            if os.path.islink(filepath) == False:
                if isElfFile(filepath):
                    countElfSize += getSize(filepath)
                    countElf += 1
                    count100Elf += 1
                    tempSectionSizes = elfSectionSizes(filepath)
                    #print("-" * 50)
                    # Print . every 100 ELF files
                    if (count100Elf == 100):
                        print(".", end=" ", flush=True)
                        count100Elf = 0
                    for section_name, size in tempSectionSizes.items():
                        if section_name in elfSectionSizeData:
                            elfSectionSizeData[section_name].append(size)
                        else:
                            elfSectionSizeData[section_name] = [size]
                        file_data['Section Name'] = name
                        file_data['Section Size'] = size
                        elfFileInfo.append(file_data)
                elif isMzFile(filepath, debug_mode):
                    count100Pe += 1
                    countPeSize += getSize(filepath)
                    countPE += 1
                    # Print size of each section
                    sectionSizes = mzSectionSizes(filepath, debug_mode)
                    # Print * every 100 PE files
                    if (count100Pe == 100) and debug_mode == 0:
                        print("*", end=" ", flush=True)
                        count100Pe = 0
                    if debug_mode:
                        print("-" * 50)
                    # Sum the sizes of each section
                    for name, size in sectionSizes.items():
                        if name in peSectionSizeData:
                            peSectionSizeData[name].append(size)
                        else:
                            peSectionSizeData[name] = [size]
                        file_data['Section Name'] = name
                        file_data['Section Size'] = size
                        peFileInfo.append(file_data)                # Should have an entry for each section in a file

# Create Pandas dataframes
elf_df = pd.DataFrame(list(elfSectionSizeData.items()), columns=['Section', 'Size'])
pe_df = pd.DataFrame(list(peSectionSizeData.items()), columns=['Section', 'Size'])

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

# Save to CSV
elf_df.to_csv('results/elf_results.csv', index=False)
pe_df.to_csv('results/pe_results.csv', index=False)

# Create Excel files
writer = pd.ExcelWriter('results/elf_results.xlsx', engine='xlsxwriter')
elf_df.to_excel(writer, sheet_name='Sheet1', index=False)
writer.close()

writer = pd.ExcelWriter('results/pe_results.xlsx', engine='xlsxwriter')
pe_df.to_excel(writer, sheet_name='Sheet1', index=False)
writer.close()

elf_file_df = pd.DataFrame(elfFileInfo)
writer = pd.ExcelWriter('results/elf_files.xlsx', engine='xlsxwriter')
elf_file_df.to_excel(writer, sheet_name='Sheet1', index=False)
writer.close()

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
print(f"\nTotal PE files: {countPE}")
print(f"Total PE file size: {countPeSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
