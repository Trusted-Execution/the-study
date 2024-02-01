import psutil
import statistics

def print_process_tree(process, depth=0, depth_data=None):
    print("  " * depth + f"|- {process.name()} (PID: {process.pid})")
    if depth_data is None:
        depth_data = []
    depth_data.append(depth)
    try:
        children = process.children()
        for child in children:
            print_process_tree(child, depth + 1, depth_data)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    if depth == 0 and depth_data:
        print(f"\nDepth Statistic for Root Proccess PID = {process.pid}")
        print(f"  Minimum Depth: {min(depth_data)}")
        print(f"  Maximum Depth: {max(depth_data)}")
        print(f"  Average Depth: {statistics.mean(depth_data)}")
        print(f"  Standard Deviation of Depth: {statistics.stdev(depth_data)}")


# Get the list of all running processes
all_processes = psutil.process_iter(['pid', 'name'])

# Iterate through each process
for process in all_processes:
    try:
        # Check if the process has a parent (i.e., it's not the root process)
        if process.parent() is None:
            print_process_tree(process, depth_data = [])
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

