import os
import sqlite3
import hashlib
from subprocess import Popen, CalledProcessError, PIPE, call

def scan_files():
    conn = sqlite3.connect('footprint.db')
    db = conn.cursor()
    
    command = 'sudo bpftrace -e \'tracepoint:syscalls:sys_enter_openat { printf("%d, %s\\n", args->flags, str(args->filename)); }\''

    with Popen(command, shell=True, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
        for index, line in enumerate(p.stdout):
            if index == 0:
                print('-- FILE SCANNER --', line, end='')
                continue
            flags, path = line.split(',')
            if '/proc' in path:
                continue
            if int(flags) & 0x0040 != 0: # O_CREAT = 0x100 flag indicates file creation in linux
                try:
                    print('-- FILE SCANNER --', line, end='')
                    path = path.strip()
                    if os.path.exists(path) and not os.path.isdir(path):
                        a_file = open(path, "rb")
                        content = a_file.read()
                        md5_hash = hashlib.md5()
                        md5_hash.update(content)
                        checksum = md5_hash.hexdigest()
                        query = f"SELECT * FROM Hashs WHERE hash='{checksum}';"
                        db.execute(query)
                        hashs = db.fetchall()
                        if hashs:
                            print('-- FILE SCANNER -- VIRUS DETECTED')
                            call(['chmod', '000', f'{path}'])
                            print('-- FILE SCANNER -- VIRUS PREVENTED')
                            hashs = None
                except FileNotFoundError:
                    continue
                except Exception as e:
                    print('++++++++++++++++++++++++++++')
                    print('- - FILE SCANNER --', e)
                    print('++++++++++++++++++++++++++++')
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)
