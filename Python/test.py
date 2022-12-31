#!/usr/bin/python3
 
 
import scapy.all as scapy
import subprocess as sp
from colorama import Back, Fore, Style
import re, requests, sys, signal, argparse, nmap, json
from pwn import *
from scapy.layers import http
import os
 
 
router_ip = sp.getoutput("route | grep default | awk '{print $2}'")
 
def sig_handler(sig, frame):
    print(Fore.YELLOW + "\n\n\t[!] " + Style.RESET_ALL + "Saliendo...\n")
    sys.exit(0)
 
signal.signal(signal.SIGINT, sig_handler)
 
ip="192.168.1.33"
nm = nmap.PortScanner()
scaneo = nm.scan(ip, '1-500', '-sS --min-rate=5000 -sCV')
print(json.dumps(scaneo, indent=1))
print(scaneo['nmap']['scanstats']['timestr'])
mac = scaneo['scan'][ip]['addresses']['mac']
print(mac)
print(scaneo['scan'][ip]['vendor'][mac])
print(scaneo['scan'][ip]['tcp'][80]['extrainfo'])
print(scaneo['scan'][ip]['tcp'][80]['script']['http-server-header'])
#print(scaneo['scan'][ip]['tcp'][80]['script']['ssl-cert'])
 
puertos = scaneo['scan'][ip]['tcp'].keys()
 
for i in puertos:
    print("Puerto %s %s %s" % (i, scaneo['scan'][ip]['tcp'][i]['extrainfo'], scaneo['scan'][ip]['tcp'][i]['product']))
 
 
netbios = scaneo['scan'][ip]['hostscript'][1]['output']
x = netbios.replace(", ","\n")
print(x)
 
print("[+] Hosts activos: %s" % (scaneo['nmap']['scanstats']['uphosts']))
 
for host in nm.all_hosts():
   print('----------------------------------------------------')
   print('Host : %s (%s)' % (host, nm[host].hostname()))
   print('State : %s' % nm[host].state())
   for proto in nm[host].all_protocols():
       print('----------')
       print('Protocol : %s' % proto)
       lport = nm[host][proto].keys()
       sorted(lport)
       for port in lport:
           print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
