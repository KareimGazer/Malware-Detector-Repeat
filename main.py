import threading
from SysMonitor import main, monitor
from Scan import cpu_limit, proc_limit, RAM_limit

if __name__ == "__main__":
    # creating threads
    t2 = threading.Thread(target=monitor, name='monitor', args=(cpu_limit, proc_limit, RAM_limit,))
    # starting threads
    t2.daemon = True
    t2.start()
    main()
