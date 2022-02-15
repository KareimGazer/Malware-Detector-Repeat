import time
from datetime import datetime
import psutil
from math import floor, pow, log
from os import getlogin
from Scan import scan

# import scan functions
# insert inside one main scan function
#def scan():
    #pass

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    sizes = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(floor(log(size_bytes, 1024)))
    p = pow(1024, i)
    s = round(size_bytes / p, 2)
    return "{} {}".format(s, sizes[i])

def get_cpu_info():
    cpu_info = dict()

    cpu_info["phys_cores"] = f"{psutil.cpu_count(logical=False)}"
    cpu_info["total_cores"] = f"{psutil.cpu_count(logical=True)}"

    cpu_freq = psutil.cpu_freq()
    cpu_info["max_freq"] = f"{cpu_freq.max:.2f}Mhz"
    cpu_info["min_freq"] = f"{cpu_freq.min:.2f}Mhz"
    cpu_info["current_freq"] = f"{cpu_freq.current:.2f}Mhz"

    cpu_usages = dict()
    for index, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        cpu_usages[f"Core {index}"] = f"{percentage}%"

    cpu_info["cpu_usages"] = cpu_usages
    total_cpu_usage = f"{psutil.cpu_percent()}%"
    cpu_info["cpu_percent_used"] = total_cpu_usage
    return cpu_info

def print_cpu_info(cpu_info):
    print("number of physical cores = ", cpu_info["phys_cores"])
    print("number of logical cores = ", cpu_info["total_cores"])

    print("current cpu freq = ", cpu_info["current_freq"])
    print("min cpu freq = ", cpu_info["min_freq"])
    print("max cpu freq = ", cpu_info["max_freq"])

    print("total cpu percentage used = ", cpu_info["cpu_percent_used"])
    print("cores info: ", cpu_info["cpu_usages"])

def get_ram_info():
    ram_info = dict()
    ram = psutil.virtual_memory()
    available_vram = convert_size(ram.available)
    used_vram = convert_size(ram.used)
    total_vram_bytes = convert_size(ram.total)
    percent_vram = f"{ram.percent}%"

    ram_info["vram_info"] = {"total_vram": total_vram_bytes, "used_vram": used_vram, "available_vram": available_vram, "percent_vram": percent_vram}
    return ram_info

def print_ram_info(ram_info):
    print("RAM info: ", ram_info["vram_info"])

def get_disk_info():
    disk_info = dict()

    disk_io = psutil.disk_io_counters()
    total_disk_read = convert_size(disk_io.read_bytes)
    total_disk_write = convert_size(disk_io.write_bytes)

    disk_info["total_disk_read"] = total_disk_read
    disk_info["total_disk_write"] = total_disk_write

    disk_info["partitions"] = []
    partitions = psutil.disk_partitions()
    for partition in partitions:
        device = partition.device
        mountpoint = partition.mountpoint
        file_sys_type = partition.fstype
        try:
            partition_usage = psutil.disk_usage(mountpoint)
        except PermissionError:
            total_disk_size = "Disk not readable"
            disk_used = "Disk not readable"
            disk_free = "Disk not readable"
            percent_used = "Disk not readable"
            disk_info["partitions"].append({"device": device, "mountpoint": mountpoint, "file_sys_type": file_sys_type,
                                        "total_disk_size": total_disk_size, "disk_used": disk_used,
                                        "percent_used": percent_used})
            continue
        total_disk_size = convert_size(partition_usage.total)
        disk_used = convert_size(partition_usage.used)
        disk_free = convert_size(partition_usage.free)
        percent_used = f"{partition_usage.percent}%"
        disk_info["partitions"].append({"device": device, "mountpoint": mountpoint, "file_sys_type": file_sys_type,
                                    "total_disk_size": total_disk_size, "disk_used": disk_used, "percent_used": percent_used})

    return disk_info

def print_disk_info(disk_info):
    print("Total Read Memory", disk_info["total_disk_read"])
    print("Total Write Memory", disk_info["total_disk_write"])
    for partition in disk_info["partitions"]:
        print("     Device Name: {}".format(partition["device"]))
        print("     MountPoint: {}".format(partition["mountpoint"]))
        print("     File System Type: {}".format(partition["file_sys_type"]))
        print("     Total Space: {}".format(partition["total_disk_size"]))
        print("     {} are used from the disk".format(partition["disk_used"]))
        print("     {}% used from disk".format(partition["percent_used"]))
        print("----------------------")

def get_network_info():
    network_info = dict()
    netowork_IO = psutil.net_io_counters()
    total_upload = convert_size(netowork_IO.bytes_sent)
    total_download = convert_size(netowork_IO.bytes_recv)
    network_info["total_upload"] = total_upload
    network_info["total_download"] = total_download
    return network_info

def print_network_info(network_info):
    print("Total Upload Data: ", network_info["total_upload"])
    print("Total Download Data: ", network_info["total_download"])

def print_battery_info():
    try:
        battery = psutil.sensors_battery()
        print("Battery info: ")
        print("     Energy: {}%".format(battery.percent))
        if(battery.power_plugged == True):
            print("     Power plugged")
        else:
            print("     No power plugged")
            print("     Time left: {} min".format(battery.secsleft / 60))
    except:
        print("     No Battery Found")

def print_summary():
    print("System Info Summary: ")
    print("User Name: ", getlogin())
    print("Boot Time: ", datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"))
    cpu_info = get_cpu_info()
    print("CPU usage: ", cpu_info["cpu_percent_used"])
    memory_info = get_ram_info()
    print("RAM usage: ", memory_info["vram_info"]["percent_vram"])
    print("Number of running processes: {}".format(len(psutil.pids())))
    print_battery_info()


def monitor(cpu_limit, proc_limit, RAM_limit):
    scan_needed = False
    while True:
        RAM = psutil.virtual_memory()
        ram_percent = RAM.percent
        cpu_percent = psutil.cpu_percent()
        proc_num = len(psutil.pids())

        if cpu_percent > cpu_limit:
            print("WARNING: CPU is overloaded {}%, run a scan ...".format(cpu_percent))
            scan_needed = True
        if  proc_num> proc_limit:
            print("WARNING: high number of processes {} run on the system, running a scan ...")
            scan_needed = True
        if ram_percent> RAM_limit:
            print("WARNING: high RAM usage {}% run a scan ...".format(ram_percent))
            scan_needed = True
        if False:
            scan()
            scan_needed = False
        time.sleep(3)

def main():
    print("System Monitor is Running: \n")
    print_summary()
    # add automatic warnings
    while True:
        print("choose info to be displayed: ")
        print("{}) exit".format(0))
        print("{}) CPU".format(1))
        print("{}) Memory".format(2))
        print("{}) Disk".format(3))
        print("{}) Network".format(4))
        print("{}) Scan".format(5))
        print("{}) Summary".format(6))
        command = input()
        if(command.isnumeric()):
            command = int(command)
        else:
            print("Please Enter a valid Number")
        if command == 0:
            exit(0)
        elif command == 1: # cpu
            cpu_info = get_cpu_info()
            print_cpu_info(cpu_info)
        elif command == 2: # mem
            mem_info = get_ram_info()
            print_ram_info(mem_info)
        elif command == 3: # disk
            disk_info = get_disk_info()
            print_disk_info(disk_info)
        elif command == 4: # net
            network_info = get_network_info()
            print_network_info(network_info)
        elif command == 5: # scan
            scan()
        elif command == 6: # sum
            print_summary()
