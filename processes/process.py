import psutil

def print_process_tree(process, depth=0, depth_data=None):
    print("  " * depth + f"|- {process.name()} (PID: {process.pid})")
    if depth_data is None:
        depth_data = []
    depth_data.append(depth)
    try:
        children = process.children()
        for child in children:
            print_process_tree(child, depth + 1)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

def main():
    # Get the list of all running processes
    all_processes = psutil.process_iter(['pid', 'name'])

    # Iterate through each process
    for process in all_processes:
        try:
            # Check if the process has a parent (i.e., it's not the root process)
            if process.parent() is None:
                print_process_tree(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

if __name__ == "__main__":
    main()

