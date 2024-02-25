#!/usr/bin/python
from datetime import datetime
import os
import time
import statistics
import argparse
import pandas as pd
from isMZ import isMzFile
from fileSize import getSize
from MzSymbols import findMzSymbols
from isElf import isElfFile
from fileSize import getSize
from elfSymbols import findElfSymbols

def parse_arguments():
    parser = argparse.ArgumentParser(description='MZ File Analysis Script')
    parser.add_argument('-debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()

countElf = 0
countElfSize = 0
count100 = 0
elfSymbolSizeData = {}
countPE = 0
countPeSize = 0
peSymbolSizeData = {}
elfFileInfo = []
peFileInfo = []
start_time = time.time()

data = []

args = parse_arguments()
debug_mode = args.debug

for subdir, dirs, files in os.walk(r"C:\Users\b135c\Downloads"):                                # Change to desired directory on system
    #if subdir.startswith(("/home", "/usr", "/etc", "/opt", "/root")):      # Comment out this line on Windows
    for file in files:
        try:
            filepath = os.path.join(subdir, file)
            filename = os.path.basename(filepath)
            _, extension = os.path.splitext(filename)
            if os.path.islink(filepath) == False:
                # Generate information on individual files
                file_data = 
                        'Type': '',
                        'File Path': filepath,
                        'File Name': filename,
                        'Extension': extension,
                        'Date Created': datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                        'File Size': getSize(filepath)
                        'Symbol Name': '',
                        'Symbol Size': ''
                    }
                count100 += 1
                if (count100 == 100) and debug_mode == 0:
                    print(".", end=" ", flush=True)
                    count100 = 0
                if isElfFile(filepath):
                    countElfSize += getSize(filepath)
                    countElf += 1
                    symbols = findElfSymbols(filepath)
                    file_data['Type'] = 'ELF'
                    if symbols is not None:
                        for symbol_name, symbol_data in symbols.items():
                            file_data['Symbol Name'] = symbol_name
                            file_data['Symbol Size'] = symbol_data['Size']
                            data.append(file_data.copy())
                        elfFileInfo.append(file_data)           # Should have an entry for each section in a file
                elif isMzFile(filepath, debug_mode):
                    countPeSize += getSize(filepath)
                    countPE += 1
                    symbols = findMzSymbols(filepath, debug_mode)
                    file_data['Type'] = 'PE'
                    if debug_mode:
                        print("-" * 50)
                    # Sum the sizes of each section
                    if symbols is not None:
                        for symbol_name, symbol_data in symbols.items():
                            file_data['Symbol Name'] = symbol_name
                            file_data['Symbol Size'] = symbol_data['Ordinal']
                            data.append(file_data.copy())
                        peFileInfo.append(file_data)                # Should have an entry for each section in a file
        except Exception as e:
                print(f"Error accessing file '{filepath}': {e}")
# Create DataFrame from the collected data
df = pd.DataFrame(data)

# Save DataFrame to CSV
df.to_csv('combined_symbol_results.csv', index=False)