#!/usr/bin/python
import socket
import time

def isOpen(y_server, port):
#        server = y_server.split('/')
        for server in servers:
          if server.endswith('.com'):
            server=server.strip()
           # break
        timeout = 3
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
                start_time = time.time()
                s.connect((server, int(port)))
                s.shutdown(socket.SHUT_RDWR)
                end_time = time.time()
                return end_time-start_time
        except:
                return False
        finally:
                s.close()

isOpen(['slc11jpg'],'22')

