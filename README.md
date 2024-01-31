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
- Uses pandas Python library to generate a CSV file with section size data
  - Excel file generation currently broken

#### Future features:
- Find all running processes on a system and count the number of libraries to make each process work
- Find and count exported symbols for every executable on a system

### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for Windows MZ executables
