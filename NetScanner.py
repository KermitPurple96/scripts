#!/usr/bin/python3


import scapy.all as scapy
import subprocess as sp
from colorama import Back, Fore, Style
import re, requests, sys, signal, argparse

url = "https://macvendors.com/query/"

def sig_handler(sig, frame):
    print(Fore.RED + "\n\n[+]" + style.RESET_ALL + "Saliendo...\n")
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
    print("\tIP\t\t\tMAC address\t\tVendor\n\t---------------------------------------------------------------")
    for client in client_list:
        response = requests.request("GET", url + client["mac"])
        print(Fore.GREEN + "\t[+] " + Style.RESET_ALL + client["ip"] + "\t\t" + client["mac"] + "\t" + response.text)


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Lista de argumentos')
    parser.add_argument('-s', '--scan', help='scan for ips in your local network', action='store_true')
    parser.add_argument('-o', '--spoof', help='set target to spoof')
    parser.add_argument('-r', '--router', help='set router to spoof')
    args = parser.parse_args()

    o = str(args.spoof)

    if args.scan:
        router_ip = sp.getoutput("route | grep default | awk '{print $2}'")
        client_list = scan(router_ip + "/24")
        print_result(client_list)
