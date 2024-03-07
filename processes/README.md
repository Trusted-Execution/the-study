This folder contains scripts that analyzes currently running processes.

### Current features:
- *currentProcesses.py* searches through a Linux system to return the currently running processes, the corresponding executables, and their dependent libraries. 
- *win_process.py* will print the currently running processes and their IDs on Windows.
- *process.py* calculates various statistics relating to the depth of processes' library dependencies. 
  - Prints hierarchy of library dependencies
  - Calculates average, minimum, maximum, and standard deviation of depth

### Python libraries utilized:
- [psutil](https://psutil.readthedocs.io/en/latest/) for analyzing Linux processes
- [pandas](https://pandas.pydata.org/) for storing data into CSV/Excel files