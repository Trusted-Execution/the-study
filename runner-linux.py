#!/usr/bin/python
import os
import struct
import time
import statistics
import pandas as pd
from isElf import isElfFile
from fileSize import getSize
from elfSectionSize import sectionSizes

countElf = 0
countElfSize = 0
count100 = 0
sectionSizeData = {}
start_time = time.time()

for subdir, dirs, files in os.walk("/"):
    if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):
        for file in files:
            file_path = os.path.join(subdir, file)
            if os.path.islink(file_path) == False:
                if isElfFile(file_path):
                    countElfSize += getSize(file_path)
                    countElf += 1
                    count100 += 1
                    tempSectionSizes = sectionSizes(file_path)
                    #print("-" * 50)
                    if (count100 == 100):
                        print(".", end=" ", flush=True)
                        count100 = 0
                    for section_name, size in tempSectionSizes.items():
                        if section_name in sectionSizeData:
                            sectionSizeData[section_name].append(size)
                        else:
                            sectionSizeData[section_name] = [size]

# Print as table
for section_name, sizes in sectionSizeData.items():
    count = len(sizes)
    average_size = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0

# Create Pandas dataframe
df = pd.DataFrame(list(sectionSizeData.items()), columns=['Section', 'Size'])

# Perform calculations
df['Avg'] = df['Size'].apply(lambda sizes: sum(sizes) / len(sizes))
df['Max'] = df['Size'].apply(max)
df['Min'] = df['Size'].apply(min)
df['Std'] = df['Size'].apply(lambda sizes: statistics.stdev(sizes) if len(sizes) >= 2 else 0.0)
df['Count'] = df['Size'].apply(len)

# Sort list alphabetically based on section name
df.sort_values('Section', inplace=True)

# Remove column with all the section sizes
df = df.drop('Size', axis=1)

# Reset the index column
df.reset_index(drop=True, inplace=True)

# Save to CSV / Excel
df.to_csv('linux_results.csv')
#df.to_excel('linux_results.xlsx') (Currently broken)

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
