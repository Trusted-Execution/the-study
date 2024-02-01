# the-study
A series of tools created to conduct research on executables and processes.

#### Current features:
- Identifies all 7FELF executables (runner-linux.py) or MZ executables (runner-windows.py) on a system
  - Excludes any symbolic links
  - Runs by default on a smaller test directory for faster testing, but can easily be changed to traverse
    entire system on Linux
- Both tools are capable of finding:
  - Overall size of each executable 
  - All sections within each executable and their individual sizes
  - Average, minimum, maximum, number, and standard deviation of section sizes based on all executables found
  - Total executables found and their combined size
##### Linux only features
- Uses pandas Python library to generate a CSV file with section size data
  - Excel file generation currently broken
- Finds currently running processes and prints their dependent libraries
  - Prints hierarchy of library dependencies
  - Calculates average, minimum, maximum, and standard deviation of depth 

#### Future features:
- Find and count exported symbols for every executable on a system

### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for analyzing Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for analyzing Windows MZ executables
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
