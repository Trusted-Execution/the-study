#!/usr/bin/python
import os
import time
from isMZ import isMzFile
from fileSize import getSize
from mzSectionSize import mzSectionSizes
import statistics

countMz = 0
countMzSize = 0
sectionSizeData = {}
start_time = time.time()

for subdir, dirs, files in os.walk(r"C:\Users\b135c\Downloads"):   # Change to your own local test directory
    for file in files:
        filepath = os.path.join(subdir, file)
        if os.path.islink(filepath) == False:
            if isMzFile(filepath):
                countMzSize += getSize(filepath)
                countMz += 1
                # Print size of each section
                sectionSizes = mzSectionSizes(filepath)
                print("-" * 50)

                # Sum the sizes of each section
                for name, size in sectionSizes.items():
                    if name in sectionSizeData:
                        sectionSizeData[name].append(size)
                    else:
                        sectionSizeData[name] = [size]

print("\nAverage, Maximum, Minimum, and Standard Deviation Section Sizes (based on raw size) across MZ Files:\n")
print("{:<25} {:<20} {:<20} {:<20} {:<20}".format("Section Name", "Average Size (bytes)", "Maximum Size", "Minimum Size", "Standard Deviation"))
for name, sizes in sectionSizeData.items():
    average = sum(sizes) / len(sizes)
    max_size = max(sizes)
    min_size = min(sizes)
    if len(sizes) >= 2:
        std = statistics.stdev(sizes)
    else:
        std = 0.0
    print("{:<25} {:<20} {:<20} {:<20} {:<20}".format(name, round(average, 2), max_size, min_size, round(std, 2)))

end_time = time.time()
elapsed_time = end_time - start_time
print(f"\nTotal MZ files: {countMz}")
print(f"Total MZ file size: {countMzSize} bytes\n")
print(f"Total runtime: {elapsed_time:.2f} seconds\n")