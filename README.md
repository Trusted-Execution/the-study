# the-study
A series of tools created to conduct research on executables and processes.

#### Current features:
- *combined_runner.py* can search through a Linux or Windows system to: 
  - Searches for both ELF (Linux) and PE (Windows) executables
    - Excludes any symbolic links
  - Generates section analysis files, which contain average, minimum, maximum, number, and standard deviation of executable section sizes
  - Generates a list of executables in the system, statistics about each file, and information about their different sections 
  - Output stored in *results* folder
  - Total executables found and their combined size
  - USAGE: `python combined_runner.py --system=*YOURSYSTEMHERE*`
    - system options: `windows` or `linux` (default: `linux`)
- *processes/* contains scripts and results related to finding currently running processes on a system
  - Prints hierarchy of library dependencies
  - Calculates average, minimum, maximum, and standard deviation of depth
- *symbols/* contains scripts that finds exported symbols for every executable on a system

### Deprecated:
- *runner-linux.py* and *runner-windows.py* were the original scripts to find ELF and PE files separately
- *linux_results* and *windows_results* are also outdated, but are there for reference for the time being
  - Likely to be removed later

### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for analyzing Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for analyzing Windows MZ executables
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
- [pandas](https://pandas.pydata.org/) for storing data into CSV/Excel files
- [XlsxWriter](https://xlsxwriter.readthedocs.io/index.html) for supplementing Excel file generation
