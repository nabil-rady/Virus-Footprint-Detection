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
    conn = sqlite3.connect('footprint.db')
    db = conn.cursor()
    
    hashs = None
    while True:
        command = f'find / -cmin 1'
        output = run(command, shell=True,capture_output=True).stdout.split()
        hashs = None
        for file in output:
            path = file.decode('utf-8') 
            if path[0] != '/' or len(path) < 5:
                continue
            print(path)
            try:
                a_file = open(f"{path}", "rb")
                content = a_file.read()
                md5_hash = hashlib.md5()
                md5_hash.update(content)
                checksum = md5_hash.hexdigest()
                query = f"SELECT * FROM Hashs WHERE hash='{str(checksum)}';"
                db.execute(query)
                hashs = db.fetchall()
                if hashs:
                    print("VIRUS DETECTED")
                    os.chmod(str(path), 0)
                    print('VIRUS PREVENTED')
                    hashs = None
            except:
                continue
        time.sleep(45)