import os
import signal
import shutil
import sqlite3
import hashlib
from subprocess import Popen, CalledProcessError, PIPE, call

def scan_processes():
    command = 'sudo bpftrace -e \'tracepoint:syscalls:sys_enter_exec*{ printf("pid: %d, comm: %s, args: ", pid, comm); join(args->argv); }\''
    
    conn = sqlite3.connect('footprint.db')
    db = conn.cursor()

    with Popen(command, shell=True, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
        for index, line in enumerate(p.stdout):
            hashs = None
            if 'md5sum' in line or 'chmod' in line:
                continue
            print('-- PROCESS SCANNER --', line, end='')
            if index != 0:
                try:
                    line = line.split(',')
                    pid = line[0].split(':')[1]
                    bin = line[1].split(':')[1]
                    args = line[2].split(':')[1].split()
                    
                    if not os.path.exists(bin):
                        bin = shutil.which(bin)
                    if bin:
                        if not os.path.isdir(bin):
                            a_file = open(bin, "rb")
                            content = a_file.read()
                            md5_hash = hashlib.md5()
                            md5_hash.update(content)
                            checksum = md5_hash.hexdigest()
                            query = f"SELECT * FROM Hashs WHERE hash='{checksum}';"
                            db.execute(query)
                            hashs = db.fetchall()
                            if hashs:
                                print('-- PROCESS SCANNER -- VIRUS STARTED')
                                os.kill(int(pid), signal.SIGKILL)
                                # os.chmod(bin, 0)
                                call(['chmod', '000', f'{bin}'])
                                print('-- PROCESS SCANNER -- VIRUS KILLED')
                                hashs = None
                    for arg in args:
                        if not os.path.exists(arg):
                            arg = shutil.which(arg)
                        if arg:
                            if not os.path.isdir(arg):
                                a_file = open(arg, "rb")
                                content = a_file.read()
                                md5_hash = hashlib.md5()
                                md5_hash.update(content)
                                checksum = md5_hash.hexdigest()
                                query = f"SELECT * FROM Hashs WHERE hash='{checksum}';"
                                db.execute(query)
                                hashs = db.fetchall()
                                if hashs:
                                    print('-- PROCESS SCANNER -- VIRUS STARTED')
                                    os.kill(int(pid), signal.SIGKILL)
                                    # os.chmod(arg, 0)
                                    call(['chmod', '000', f'{arg}'])
                                    print('-- PROCESS SCANNER -- VIRUS KILLED')
                                    hashs = None
                except Exception as e:
                    print('++++++++++++++++++++++++++++')
                    print('- - PROCESS SCANNER --', e)
                    print('++++++++++++++++++++++++++++')
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)
