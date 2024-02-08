#!/usr/bin/python
import os
import time
from isMZ import isMzFile
from fileSize import getSize
from mzSectionSize import mzSectionSizes
import statistics
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(description='MZ File Analysis Script')
    parser.add_argument('-debug', type=int, default=0, help='Enable debugging mode (1 for yes, 0 for no)')
    return parser.parse_args()


countMz = 0
countMzSize = 0
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
            if (count100 == 100):
                print(".", end=" ", flush=True)
                count100 = 0
            if isMzFile(filepath, debug_mode):
                countMzSize += getSize(filepath)
                countMz += 1
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

print("\nMZ File Section Analysis:\n")
print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format("Section Name", "Avg (bytes)", "Max", "Min", "STD", "Count"))
for name, sizes in sectionSizeData.items():
    count = len(sizes)
    average = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0
    print("{:<30} {:<20} {:<20} {:<10} {:<15} {:<8}".format(name, round(average, 2), max_size, min_size, round(std, 2), count))

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal MZ files: {countMz}")
print(f"Total MZ file size: {countMzSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")
