# this file is used to collect all scan functions
proc_limit = 500
cpu_limit = 80
RAM_limit = 80
def scan():
    import os
    import threading
    import csv
    from sys import stdout
    from operator import itemgetter
    from time import sleep,time
    from signal import SIGKILL, SIGSTOP, SIGCONT
    import time
    global stop_threads



    self_pid = str(os.getpid())

    with open('/proc/self/status') as file:
        status_list = file.readlines()

    status_names = []

    for s in status_list:
        status_names.append(s.split(':')[0])

    ppid_index = status_names.index('PPid')
    uid_index = status_names.index('Uid')

    PROC_NUM = 50
    TIME = 5
    PRINT_NPROC = 10

##########################################################################

    # FUNCS

    def rline1(path):
        """read 1st line from path."""
        try:
            with open(path) as f:
                for line in f:
                    return line[:-1]
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''


    def pid_to_uid(pid):
        '''return euid'''
        try:

            with open('/proc/' + pid + '/status') as f:
                for n, line in enumerate(f):
                    if n is uid_index:
                        return line.split('\t')[2]
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''


    def pid_to_name(pid):
        try:
            with open('/proc/' + pid + '/status') as f:
                for line in f:
                    return line[:-1].split('\t')[1]
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''


    def pid_to_ppid(pid):
        try:
            with open('/proc/' + pid + '/status') as f:
                for n, line in enumerate(f):
                    if n is ppid_index:
                        return line.split('\t')[1].strip()
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''


    def pid_to_cmdline(pid):
        try:
            with open('/proc/' + pid + '/cmdline') as f:
                try:
                    for line in f:
                        return line.replace('\x00', ' ').strip()
                except IndexError:
                    return ''
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''


    def pid_to_state(pid):
        try:
            return rline1('/proc/' + pid + '/stat').rpartition(')')[2][1]
        except FileNotFoundError:
            return ''
        except ProcessLookupError:
            return ''
        except IndexError:
            return ''


    def find_bomb_pattern(pid_set):
        # need rename to find_bomb_name
        name_dict = dict()
        for pid in pid_set:
            name = pid_to_name(pid)
            if name == '':
                continue
            if name not in name_dict:
                name_dict[name] = 1
            else:
                name_dict[name] += 1
        x = name_dict.items()
        y = sorted(x, key=itemgetter(1))
        return y[-1][0]


    def find_bomb_cmdline():
        cmdline_dict = dict()
        for pid in os.listdir('/proc'):
            if pid[0].isdecimal() == False or pid == '1' or pid == self_pid or pid_to_state(
                    pid) != 'T':
                continue
            cmdline = pid_to_cmdline(pid)
            if cmdline == '':
                continue
            if cmdline not in cmdline_dict:
                cmdline_dict[cmdline] = 1
            else:
                cmdline_dict[cmdline] += 1
        x = cmdline_dict.items()
        y = sorted(x, key=itemgetter(1))
        try:
            return y[-1][0]
        except IndexError:
            return ''


    def find_bomb_uid():
        uid_dict = dict()
        for pid in os.listdir('/proc'):
            if pid[0].isdecimal() == False or pid == '1' or pid == self_pid or pid_to_state(
                    pid) != 'T':
                continue
            uid = pid_to_uid(pid)
            if uid == '':
                continue
            if uid not in uid_dict:
                uid_dict[uid] = 1
            else:
                uid_dict[uid] += 1
        x = uid_dict.items()
        y = sorted(x, key=itemgetter(1))
        return y[-1][0]


    def find_bomb_ppid():
        ppid_dict = dict()
        for pid in os.listdir('/proc'):
            if pid[0].isdecimal() == False or pid == '1' or pid == self_pid or pid_to_state(
                    pid) != 'T':
                continue
            ppid = pid_to_ppid(pid)
            if ppid == '':
                continue
            if ppid not in ppid_dict:
                ppid_dict[ppid] = 1
            else:
                ppid_dict[ppid] += 1
        x = ppid_dict.items()
        y = sorted(x, key=itemgetter(1))
        return y[-1][0]


    def stop_the_world1(bomb_name):
        stop_counter = 0
        for pid in os.listdir('/proc'):
            if pid[0].isdecimal() is False:
                continue
            name = pid_to_name(pid)
            if name == bomb_name:
                try:
                    os.kill(int(pid), SIGSTOP)
                except FileNotFoundError:
                    pass
                except ProcessLookupError:
                    pass
                stop_counter += 1
        return stop_counter


    def stop_the_world(bomb_name):
        x0 = -1
        while True:
            x = stop_the_world1(bomb_name)
            if x == x0:
                return None
            x0 = x


    def kill_stopped(bomb_name):
        kill_counter = 0
        for pid in os.listdir('/proc'):

            if pid[0].isdecimal() is False:
                continue

            name = pid_to_name(pid)

            try:
                state = pid_to_state(pid)
            except FileNotFoundError:
                state = ''
            except ProcessLookupError:
                state = ''

            cmdline = pid_to_cmdline(pid)

            if name == bomb_name and cmdline == bomb_cmdline and state == 'T':

                try:
                    os.kill(int(pid), SIGKILL)
                    kill_counter += 1
                except FileNotFoundError:
                    pass
                except ProcessLookupError:
                    pass




    def cont_stopped(bomb_name):
        cont_counter = 0
        for pid in os.listdir('/proc'):
            if pid[0].isdecimal() is False:
                continue
            state = pid_to_state(pid)
            name = pid_to_name(pid)

            if state == 'T' and name == bomb_name:
                try:
                    cmdline = pid_to_cmdline(pid)
                    os.kill(int(pid), SIGCONT)
                    cont_counter += 1
                except FileNotFoundError:
                    pass
                except ProcessLookupError:
                    pass




##########################################################################
    raw_data_file = "processes.txt"
    # return a dictionary {PID: VSZ} for all processes
    def get_proc_mem(raw_data_file):
        # file to store processes data after cleaning
        cleanProcData = open("procs.csv", 'w')
        # processing the data
        with open(raw_data_file, newline='\n') as csvfile:
            for row in csvfile:
                writer = csv.writer(cleanProcData)
                writer.writerow(row.split())
        cleanProcData.close()

        # getting the needed info
        with open("procs.csv", newline='\n') as csvfile:
            file_read = csv.reader(csvfile)
            info_table = list(file_read)
            PID = [row[1] for row in info_table]
            VSZ = [row[4] for row in info_table]
        result =  dict(zip(PID, VSZ))
        del result["PID"]
        return result

    def scan():
        # using shell command to get processes info into a file
        os.system("ps -aux >> {}".format(raw_data_file))
        # getting the data formatted in dictionary
        info1 = get_proc_mem(raw_data_file)
        time.sleep(5)
        os.system("ps -aux >> {}".format(raw_data_file))
        info2 = get_proc_mem(raw_data_file)
        time.sleep(5)
        os.system("ps -aux >> {}".format(raw_data_file))
        info3 = get_proc_mem(raw_data_file)
        time.sleep(5)
        os.system("ps -aux >> {}".format(raw_data_file))
        info4 = get_proc_mem(raw_data_file)

        # measuring the memory consumption for each process in MB
        results = dict()
        for pid in info2:
            diff1 = int(info2.get(pid, 0)) - int(info1.get(pid, 0))
            diff2 = int(info4.get(pid, 0)) - int(info3.get(pid, 0))
            if diff1 == diff2 and diff1 != 0 :
                diff = True
            else:
                diff = False
            results[pid] = diff

        black_list = list() # list of suspicious processes
        for key in results:
            if results[key] == True:
                black_list.append(key)
        return black_list

    # detects the program by scanning multiple times
    # to make sure the memory usage is periodic
    def detect(iterations_num=2):
        # using sets to detect repeated processes
        suspicious = set()
        for i in range(iterations_num):
            iter_result = set(scan())
            if i == 0:
                suspicious = iter_result
            else:
                suspicious = suspicious.intersection(iter_result)
        return list(suspicious)


##########################################################


    pid_set = set(os.listdir('/proc'))


    stdout.flush()


    while True:
        stdout.flush()
        sleep(TIME)
        new_set = set(os.listdir('/proc'))
        delta = new_set - pid_set
        pid_set = new_set

        if len(delta) > PROC_NUM:
            bomb_name = find_bomb_pattern(delta)
            stop_the_world(bomb_name)
            bomb_cmdline = find_bomb_cmdline()
            bomb_uid = find_bomb_uid()
            bomb_ppid = find_bomb_ppid()
            if bomb_ppid != '1':
                os.kill(int(bomb_ppid), SIGKILL)
            kill_stopped(bomb_name)
            cont_stopped(bomb_name)

            print('\n  Bomb name:   ', bomb_name,
                '\n  Bomb cmdline:', bomb_cmdline,
                '\n  Bomb eUID:   ', bomb_uid,
                '\n  Bomb PPid:   ', bomb_ppid, '\n', '=' * 78)

        malware_list = detect()
        name=[]
        if len(malware_list) > 0:
            for pid in malware_list:
                os.kill(int(pid), SIGSTOP)
                name.append(pid_to_name(pid))
            print("these process {} are suspicious ".format(name))
            op1 = input("Do you want to kill or continue ? 'k' or 'c' ").lower()
            if op1 == 'd':
                for pid in malware_list:
                    os.kill(int(pid), SIGKILL)
            elif op1 == 'c':
                for pid in malware_list:
                    os.kill(int(pid), SIGCONT)
        #print("No New Malwares Detected")    
        op = input("Do you want to scan again ? 'y' or 'n' ").lower()

        if op == 'y' :
            continue
        if op == 'n' :
            break
    
    
    
    
    
    
    
    
    
    
    
    
    
