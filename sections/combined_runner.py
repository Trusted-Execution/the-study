#!/usr/bin/python
import os
import struct
import time
import statistics
import pandas as pd
import platform
import sys
 
# setting path
sys.path.append('../utils')

from datetime import datetime
from utils.isElf import isElfFile
from utils.isMZ import isMzFile
from utils.fileSize import getSize
from elfSectionSize import elfSectionSizes
from mzSectionSize import mzSectionSizes

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

elf_df['Type'] = 'ELF'
elf_file_df['Type'] = 'ELF'
pe_df['Type'] = 'PE'
pe_file_df['Type'] = 'PE'

# Create merged dataframes
section_analysis_df = pd.concat([elf_df[['Type'] + elf_df.columns[:-1].tolist()], pe_df[['Type'] + pe_df.columns[:-1].tolist()]])
executable_files_df = pd.concat([elf_file_df[['Type'] + elf_file_df.columns[:-1].tolist()], pe_file_df[['Type'] + pe_file_df.columns[:-1].tolist()]])

# Generate results and store in correct folder based on system
if current_system == 'Linux':
    # Executable section analysis
    elf_df.to_csv('results/linux/elf_section_analysis.txt', sep='\t', index=False)
    pe_df.to_csv('results/linux/pe_section_analysis.txt', sep='\t', index=False) 
    section_analysis_df.to_csv('results/linux/all_executable_section_analysis.txt', sep='\t', index=False)
    # Lists of executables
    elf_file_df.to_csv('results/linux/elf_files_with_sections.txt', sep='\t', index=False)
    pe_file_df.to_csv('results/linux/pe_files_with_sections.txt', sep='\t', index=False)
    executable_files_df.to_csv('results/linux/all_executables_with_sections.txt', sep='\t', index=False)
    print("\n\nResults written to ./results/linux/")
elif current_system == 'Windows':
    # Executable section analaysis
    elf_df.to_csv('results/windows/elf_section_analysis.txt', sep='\t', index=False)
    pe_df.to_csv('results/windows/pe_section_analysis.txt', sep='\t', index=False)
    section_analysis_df.to_csv('results/windows/all_executable_section_analysis.txt', sep='\t', index=False)
    # Lists of executables
    elf_file_df.to_csv('results/windows/elf_files_with_sections.txt', sep='\t', index=False)
    try:
        pe_file_df.to_csv('results/windows/pe_files_with_sections.txt', sep='\t', index=False, encoding='utf-8')
        executable_files_df.to_csv('results/windows/all_executables_with_sections.txt', sep='\t', index=False)
    except UnicodeEncodeError:
        pe_file_df.applymap(lambda x: x.encode('unicode_escape').decode('utf-8') if isinstance(x, str) else x).to_csv('results/windows/pe_files_with_sections.txt', sep='\t', index=False, encoding='utf-8')
        executable_files_df.applymap(lambda x: x.encode('unicode_escape').decode('utf-8') if isinstance(x, str) else x).to_csv('results/windows/all_executables_with_sections.txt', sep='\t', index=False, encoding='utf-8')
    print("\n\nResults written to ./results/windows/")

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
print(f"\nTotal PE files: {countPE}")
print(f"Total PE file size: {countPeSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
