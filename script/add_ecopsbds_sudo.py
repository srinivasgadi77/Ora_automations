#!/usr/bin/python

import os
import commands
import sys
import getpass
import platform
import socket
import shutil

def identity():
    if getpass.getuser() == 'root' or not os.getuid():
        print('Executing with privileges')
        return True
    else:
        sys.exit('Script must be executed with escalated privileges')
        return False

def backup_sudofile():
    shutil.copy("/etc/sudoers","/etc/sudoers_202201_org")

def id_exists_sudoers():
    sudo_file = open("/etc/sudoers","r")
    readfile = sudo_file.read()

    if "ecopsbds" in readfile:
       sys.exit('%s : user ecopsbds already exist' %socket.gethostname())
    else:
      backup_sudofile()
      add_sudoers()

def add_sudoers():
    entry_line = "ecopsbds ALL=(ALL) ALL"

    data = open("/etc/sudoers","a")
    data.write(entry_line + "\n")    
    data.close
    sys.exit ('%s : updated sudo file successfully' %socket.gethostname())

def check_ecops_exists():
    cmd = "id ecopsbds"
    status, output = commands.getstatusoutput(cmd)
    if status == 0 and output:
       id_exists_sudoers()
    else:
     sys.exit('%s : user ecopsbds does not exists ' %socket.gethostname())

check_ecops_exists()

