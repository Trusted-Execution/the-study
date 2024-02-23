#!/usr/bin/python
import os
import time
from isMZ import isMzFile
from fileSize import getSize
from MzSymbols import findSymbols
import statistics
import argparse
import pandas as pd


def parse_arguments():
    parser = argparse.ArgumentParser(description='MZ File Analysis Script')
    parser.add_argument('-debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()


countPE = 0
countPeSize = 0
count100 = 0
symbolSizeData = {}
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
                symbols = findSymbols(filepath, debug_mode)
                if debug_mode:
                    print("-" * 50)
                # Sum the sizes of each section
                if symbols is not None:
                    for symbol_name, symbol_data in symbols.items():
                        if symbol_name in symbolSizeData:
                            symbolSizeData[symbol_name]['Size'].append(symbol_data['Ordinal'])
                        else:
                            symbolSizeData[symbol_name] = {
                                    'Size': [symbol_data['Ordinal']],
                                    'Type': 'Exported',
                                    }


#print("\nPE File Section Analysis:\n")
#print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format("Section Name", "Avg (bytes)", "Max", "Min", "STD", "Count"))
# for name, sizes in symbolSizeData.items():
#     count = len(sizes)
#     average = sum(sizes) / len(sizes)
#     max_size = max(sizes)
#     min_size = min(sizes)
#     if len(sizes) >= 2:
#         std = statistics.stdev(sizes)
#     else:
#         std = 0.0
    #print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format(name, round(average, 2), max_size, min_size, round(std, 2), count))

df = pd.DataFrame(list(symbolSizeData.items()), columns=['Symbol', 'Data'])

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
df.to_csv('windows_symbol_results.csv')


end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal PE files: {countPE}")
print(f"Total PE file size: {countPeSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
