#!/usr/bin/env python3

import threading
from files_scanner import scan_files
from processes_scanner import scan_processes

t1 = threading.Thread(target=scan_files)
t2 = threading.Thread(target=scan_processes)

t1.start()
t2.start()
