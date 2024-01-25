#!/usr/bin/python
import os

def getSize(file_path):
    # Get the stats on the file
    file_stats = os.stat(file_path)
    file_size = file_stats.st_size
    print(f"Size of file = {file_size}")
    return file_size
