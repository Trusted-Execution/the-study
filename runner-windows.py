#!/usr/bin/python
import os
import time
from isMZ import isMzFile
from fileSize import getSize
from mzSectionSize import mzSectionSizes
import statistics
import argparse
import pandas as pd


def parse_arguments():
    parser = argparse.ArgumentParser(description='PE File Analysis Script')
    parser.add_argument('-debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()


countPE = 0
countPeSize = 0
count100 = 0
sectionSizeData = {}
start_time = time.time()

args = parse_arguments()
debug_mode = args.debug

for subdir, dirs, files in os.walk(r"C:\\"):   # Change to your own local test directory
    for file in files:
        filepath = os.path.join(subdir, file)
        if os.path.islink(filepath) == False:
            count100 += 1
            if (count100 == 100) and debug_mode == 0:
                print(".", end=" ", flush=True)
                count100 = 0
            if isMzFile(filepath, debug_mode):
                countPeSize += getSize(filepath)
                countPE += 1
                # Print size of each section
                sectionSizes = mzSectionSizes(filepath, debug_mode)
                if debug_mode:
                    print("-" * 50)
                # Sum the sizes of each section
                for name, size in sectionSizes.items():
                    if name in sectionSizeData:
                        sectionSizeData[name].append(size)
                    else:
                        sectionSizeData[name] = [size]

#print("\nPE File Section Analysis:\n")
#print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format("Section Name", "Avg (bytes)", "Max", "Min", "STD", "Count"))
for name, sizes in sectionSizeData.items():
    count = len(sizes)
    average = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0
    #print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format(name, round(average, 2), max_size, min_size, round(std, 2), count))

df = pd.DataFrame(list(sectionSizeData.items()), columns=['Section', 'Size'])

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

# Save to CSV
df.to_csv('windows_results.csv')

writer = pd.ExcelWriter('windows_results.xlsx', engine='xlsxwriter')
df.to_excel(writer, sheet_name='Sheet1')
writer.close()

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal PE files: {countPE}")
print(f"Total PE file size: {countPeSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
