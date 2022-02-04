from subprocess import Popen, PIPE, CalledProcessError

command = 'sudo bpftrace -e \'tracepoint:syscalls:sys_enter_exec*{ printf("pid: %d, comm: %s, args: ", pid, comm); join(args->argv); }\''
pattern = 'grep -v "scanner.py\|md5sum"'

print(command + ' | ' + pattern)

with Popen(command + ' | ' + pattern, shell=True, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
    for line in p.stdout:
        print(line, end='')

print('Anything')

if p.returncode != 0:
    raise CalledProcessError(p.returncode, p.args)