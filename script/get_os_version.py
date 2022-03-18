#!/usr/bin/python
import platform

def get_os_version():
    return eval(platform.dist()[1].split('.')[0])


print(get_os_version())


