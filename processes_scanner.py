from ast import While
from curses import echo
import os
import signal
import shutil
from subprocess import Popen, CalledProcessError, check_output, run, PIPE
import sqlite3
import hashlib
import time

if __name__ == '__main__':  
    command = 'sudo bpftrace -e \'tracepoint:syscalls:sys_enter_exec*{ printf("pid: %d, comm: %s, args: ", pid, comm); join(args->argv); }\''
    
    conn = sqlite3.connect('footprint.db')
    db = conn.cursor()

    with Popen(command, shell=True, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
        for index, line in enumerate(p.stdout):
            hashs = None
            if 'md5sum' in line or 'scanner.py' in line:
                continue
            print(line, end='')
            if index != 0:
                try:
                    line = line.split(',')
                    pid = line[0].split(':')[1]
                    bin = line[1].split(':')[1]
                    args = line[2].split(':')[1].split()
                    
                    if not os.path.exists(bin):
                        bin = shutil.which(bin)
                    if bin:
                        a_file = open(f"{bin[2:]}", "rb")
                        content = a_file.read()
                        md5_hash = hashlib.md5()
                        md5_hash.update(content)
                        checksum = md5_hash.hexdigest()
                        query = f"SELECT * FROM Hashs WHERE hash='{str(checksum)}';"
                        db.execute(query)
                        hashs = db.fetchall()
                        if hashs:
                            print("VIRUS STARTED")
                            os.kill(int(pid), signal.SIGKILL)
                            os.chmod(str(bin), 0)
                            print('VIRUS KILLED')
                            hashs = None
                    for arg in args:
                        if not os.path.exists(arg):
                            arg = shutil.which(arg)
                        if arg:
                            a_file = open(f"{arg[2:]}", "rb")
                            content = a_file.read()
                            md5_hash = hashlib.md5()
                            md5_hash.update(content)
                            checksum = md5_hash.hexdigest()
                            query = f"SELECT * FROM Hashs WHERE hash='{str(checksum)}';"
                            db.execute(query)
                            hashs = db.fetchall()
                            if hashs:
                                print("VIRUS STARTED")
                                os.kill(int(pid), signal.SIGKILL)
                                os.chmod(str(arg), 0)
                                print('VIRUS KILLED')
                                hashs = None
                except Exception as e:
                    print('++++++++++++++++++++++++++++')
                    print(e)
                    print('++++++++++++++++++++++++++++')
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)