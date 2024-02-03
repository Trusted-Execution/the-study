import os
import pandas as pd

def get_exe_info(pid):
    try:
        # Get the executable path
        exe_path = os.path.realpath(f"/proc/{pid}/exe")
        # Get the associated library
        maps_path = f"/proc/{pid}/maps"
        with open(maps_path, 'r') as maps_file:
            libraries = []
            # Look at each line and fetch directories
            for line in maps_file:
                current_line = line.strip()
                # If the current line is not empty
                if current_line != '':
                    # Get dependent library
                    library = current_line.split()[-1]
                    # Only add to library list if not duplicate
                    if library not in libraries:
                        if library != '0' and not library.startswith('['):
                            libraries.append(library)
            # If the library list is not empty
            if libraries:
                return exe_path, libraries


    except Exception as e:
        # Ignoring printing the error because not checking map size...will have error of no exe dir
        # print(f"Error processing PID {pid}: {e}")
        return 0, 0

proc_dir = "/proc"
data = []   # Dictionary to hold data to create pandas dataframe

# Iterate through directories in /proc
for pid in os.listdir(proc_dir):
    if pid.isdigit():
        maps_path = f"{proc_dir}/{pid}/maps"
        # Check if path exists (used to check if empty but it wouldnt work because it would say all is empty?)
        if os.path.exists(maps_path): #and os.path.getsize(maps_path) > 0:
            # Get executable information
            exe_path, libraries = get_exe_info(pid)
            # Print if both are not empty
            if exe_path and libraries:
                data.append({
                    "PID": pid,
                    "Executable": exe_path,
                    "Libraries": libraries
                })

# Create pandas dataframe
df = pd.DataFrame(data)

# Convert to CSV file
df.to_csv("currentProcessData.csv", index=False)

