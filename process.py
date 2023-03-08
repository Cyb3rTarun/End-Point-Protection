import psutil
import matplotlib.pyplot as plt

# Get a list of all running processes
processes = psutil.process_iter()

# Create a dictionary to store the number of file accesses for each process
file_accesses = {}

# Loop through each process and count the number of file accesses
for process in processes:
    try:
        process_name = process.name()
        p = psutil.Process(process.pid)
        files = p.open_files()
        file_count = len(files)
        if process_name in file_accesses:
            file_accesses[process_name] += file_count
        else:
            file_accesses[process_name] = file_count
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Ignore any processes that cannot be accessed or do not exist
        pass

# Create a bar chart of the number of file accesses for each process
names = list(file_accesses.keys())
values = list(file_accesses.values())
plt.bar(names, values)
plt.xticks(rotation=90)
plt.xlabel('Process Name')
plt.ylabel('Number of File Accesses')
plt.show()


import psutil

# Print header
print("PID\tNAME\t\t\t\t\tSTATUS\t CPU%\tMEM%\tELEVATED\tNETACTIVITY")

# Loop indefinitely
while True:
    # Get list of all running processes
    for proc in psutil.process_iter():
        try:
            # Get process details
            pid = proc.pid
            name = proc.name()
            status = proc.status()
            cpu_percent = proc.cpu_percent(interval=0.1)
            mem_percent = proc.memory_percent()
            is_elevated = False
            has_network_activity = False

            # Check if process is running with elevated privileges
            if psutil.Process(pid).username() == "root":
                is_elevated = True

            # Check if process has network activity
            connections = psutil.net_connections()
            for conn in connections:
                if conn.pid == pid and conn.status == "ESTABLISHED":
                    has_network_activity = True

            # Check for security issues
            if "malware" in name.lower():
                print("{:<8} {:<39} {:<8} {:<8.1f} {:<8.1f} {:<12} {:<12}".format(pid, name, status, cpu_percent, mem_percent, is_elevated, has_network_activity))
            elif cpu_percent > 80:
                print("{:<8} {:<39} {:<8} {:<8.1f} {:<8.1f} {:<12} {:<12}".format(pid, name, status, cpu_percent, mem_percent, is_elevated, has_network_activity))
            elif is_elevated:
                print("{:<8} {:<39} {:<8} {:<8.1f} {:<8.1f} {:<12} {:<12}".format(pid, name, status, cpu_percent, mem_percent, is_elevated, has_network_activity))
            elif has_network_activity:
                print("{:<8} {:<39} {:<8} {:<8.1f} {:<8.1f} {:<12} {:<12}".format(pid, name, status, cpu_percent, mem_percent, is_elevated, has_network_activity))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Ignore any errors that occur
            pass

