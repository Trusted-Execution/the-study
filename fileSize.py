#!/usr/bin/python
import os

def convertBytes(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0

def getSize(file_path):
    # Get the stats on the file
    file_stats = os.stat(file_path)
    file_size = file_stats.st_size
    converted_size = convertBytes(file_size)
    print(f"Size of file = {converted_size}")
    return file_size
