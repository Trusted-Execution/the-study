import wmi

# Initializing the wmi constructor
f = wmi.WMI()

# Printing the header for the later columns
print("pid\tProcess name\n")

# Iterating through all the running processes
for process in f.Win32_Process():
    # Displaying the P_ID and P_Name of the process
    print(f"{process.ProcessId}\t{process.Name}", flush=True)