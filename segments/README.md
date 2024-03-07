This folder contains scripts that analyzes segments for every executable on a system

### Current features:
- *segment_runner.py* can search through a Linux or Windows system to: 
  - Search for both ELF (Linux) and PE (Windows) executables
    - Excludes any symbolic links
  - Generate a file that gives a summary for segments that are separated by ELF files, and PE files (further separated by types of sizes)
  - Store output in *results/* folder
  - USAGE: `python segment_runner.py`
    - windows also has a `--debug` option: 0 for on or 1 for off (default: 0)


### Python libraries utilized:
- [pyelftools](https://github.com/eliben/pyelftools) for analyzing Linux 7FELF executables
- [pefile](https://github.com/erocarrera/pefile) for analyzing Windows MZ executables
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
- [pandas](https://pandas.pydata.org/) for storing data into CSV/Excel files
- [XlsxWriter](https://xlsxwriter.readthedocs.io/index.html) for supplementing Excel file generation
