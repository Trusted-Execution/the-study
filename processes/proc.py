import os

def get_exe_info(pid):
    try:
        # Get the executable path
        exe_path = os.path.realpath(f"/proc/{pid}/exe")
        # Get the associated library
        maps_path = f"/proc/{pid}/maps"
        with open(maps_path, 'r') as maps_file:
            # Read first line of the maps file
            line = maps_file.readline()
            # Make sure its not just empty space
            if line.strip() != '':
                # Get library info
                library = line.split()[-1]
                return exe_path, library
    except Exception as e:
        # Ignoring printing the error because not checking map size...will have error of no exe dir
        # print(f"Error processing PID {pid}: {e}")
        return 0, 0

proc_dir = "/proc"

# Iterate through directories in /proc
for pid in os.listdir(proc_dir):
    if pid.isdigit():
        maps_path = f"{proc_dir}/{pid}/maps"
        # Check if path exists (used to check if empty but it wouldnt work because it would say all is empty?
        if os.path.exists(maps_path): #and os.path.getsize(maps_path) > 0:
            # Get executable information
            exe_path, library = get_exe_info(pid)
            # Print if both arent None
            if exe_path and library:
                print(f"PID: {pid}\nExecutable: {exe_path}\nLibrary: {library}\n")
