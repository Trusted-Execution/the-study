#!/usr/bin/python
import os

def getSize(filepath):
    file_stats = os.stat(filepath)
    file_size = file_stats.st_size
    print(f"Size of file = {file_size}")
    return file_size
