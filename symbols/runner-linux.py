#!/usr/bin/python
import os
import struct
import time
import statistics
import pandas as pd
from isElf import isElfFile
from fileSize import getSize
from elfSymbols import findSymbols
from elftools.elf.elffile import ELFFile


countElf = 0
countElfSize = 0
count100 = 0
symbolSizeData = {}
start_time = time.time()

for subdir, dirs, files in os.walk("/usr"):
    #if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):
        for file in files:
            file_path = os.path.join(subdir, file)
            if os.path.islink(file_path) == False:
                if isElfFile(file_path):
                    countElfSize += getSize(file_path)
                    countElf += 1
                    count100 += 1
                    symbols = findSymbols(file_path)
                    #print("-" * 50)
                    if (count100 == 100):
                        print(".", end=" ", flush=True)
                        count100 = 0
                    if symbols is not None:
                        for symbol_name, symbol_data in symbols.items():
                            if symbol_name in symbolSizeData:
                                symbolSizeData[symbol_name]['Size'].append(symbol_data['Size'])
                            else:
                                symbolSizeData[symbol_name] = {
                                        'Size': [symbol_data['Size']],
                                        'Type': symbol_data['Type'],
                                        }

# Print as table
'''
for symbol_name, sizes in symbolSizeData.items():
    count = len(sizes)
    average_size = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0
'''
# Create Pandas dataframe
df = pd.DataFrame(list(symbolSizeData.items()), columns=['Symbol', 'Data'])

# Extract Size and Type from Data column
df['Size'] = df['Data'].apply(lambda data: data['Size'] if isinstance(data['Size'], list) else [data['Size']])
df['Type'] = df['Data'].apply(lambda data: data['Type'])
df.drop('Data', axis=1, inplace=True)

# Perform calculations
df['Avg'] = df['Size'].apply(lambda data: sum(data) / len(data) if len(data) > 0 else 0.0)
df['Max'] = df['Size'].apply(lambda data: max(data) if len(data) > 0 else 0.0)
df['Min'] = df['Size'].apply(lambda data: min(data) if len(data) > 0 else 0.0)
df['Std'] = df['Size'].apply(lambda data: statistics.stdev(data) if len(data) >= 2 else 0.0)
df['Count'] = df['Size'].apply(lambda data: len(data))

# Add Flags column
df['Flags'] = df['Type']

# Select the desired columns
df = df[['Symbol', 'Avg', 'Max', 'Min', 'Std', 'Count', 'Flags']]

# Sort list alphabetically based on symbol name
df.sort_values('Symbol', inplace=True)

# Reset the index column
df.reset_index(drop=True, inplace=True)

# Save to CSV / Excel
df.to_csv('linux_symbol_results.csv')
#df.to_excel('linux_symbol_results.xlsx') (Currently broken)

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal ELF files: {countElf}")
print(f"Total ELF file size: {countElfSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
