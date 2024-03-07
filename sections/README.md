This folder contains scripts that analyzes sections for every executable on a system

### Current features:
- *combined_runner.py* can search through a Linux or Windows system to: 
  - Search for both ELF (Linux) and PE (Windows) executables
    - Excludes any symbolic links
  - Generate section analysis files
    - Contains average, minimum, maximum, number, and standard deviation of executable section sizes
  - Generate a list of executables in the system and data about each file
    - Also generates a list of each executable's different sections
  - Calculate total executables (ELF/PE) found and their combined size
  - Store output in *results/* folder
    - Automatically detects whether system is Windows or Linux and stores results in the appropriate subfolder 

### Deprecated:
- *runner-linux.py* and *runner-windows.py* were the original scripts to find ELF and PE files separately

### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for analyzing Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for analyzing Windows MZ executables
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
- [pandas](https://pandas.pydata.org/) for storing data into CSV/Excel files
