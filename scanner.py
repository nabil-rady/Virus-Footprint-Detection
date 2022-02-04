import os 
import shutil
from subprocess import Popen, CalledProcessError, check_output, run, PIPE

if __name__ == '__main__':  
    command = 'sudo bpftrace -e \'tracepoint:syscalls:sys_enter_exec*{ printf("pid: %d, comm: %s, args: ", pid, comm); join(args->argv); }\''
    
    with Popen(command, shell=True, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
        for index, line in enumerate(p.stdout):
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
                        checksum = check_output(f'sudo md5sum {bin}', shell=True).split()[0]
                        if checksum == b'bc80a17d8a16e91b9aaf13b5431ac445':
                            print("VIRUS STARTED")
                            run(f'sudo kill -9 {pid}', shell=True)
                            print('VIRUS KILLED')
                    for arg in args:
                        if not os.path.exists(arg):
                            arg = shutil.which(arg)
                        if arg:
                            checksum = check_output(f'sudo md5sum {arg}', shell=True).split()[0]
                            if checksum == b'bc80a17d8a16e91b9aaf13b5431ac445':
                                print("VIRUS STARTED")
                                run(f'sudo kill -9 {pid}', shell=True)
                                print('VIRUS KILLED')
                except Exception as e:
                    print('++++++++++++++++++++++++++++')
                    print(e)
                    print('++++++++++++++++++++++++++++')
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)