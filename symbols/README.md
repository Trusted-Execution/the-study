This folder contains scripts that finds exported symbols for every executable on a system

#### Current features:
- *combined_runner.py* can search through a Linux or Windows system to: 
  - Search for both ELF (Linux) and PE (Windows) executables
    - Excludes any symbolic links
  - Generate files that list each symbol and size along with the file information
    - Generates both .csv and .txt files
  - Store output in *results/* folder
  - USAGE: `python combined_runner.py --system=*YOURSYSTEMHERE*`
    - system options: `windows` or `linux` (default: `linux`)
    - windows also has a --debug option: 0 for on or 1 for off (default: 0)

### Deprecated:
- *runner-linux.py* and *runner-windows.py* were the original scripts to find ELF and PE files separately

### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for analyzing Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for analyzing Windows MZ executables
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
- [pandas](https://pandas.pydata.org/) for storing data into CSV/Excel files
