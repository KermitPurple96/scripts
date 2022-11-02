#!/bin/bash

function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        tput cnorm;exit 1
}

#Ctrl+C
trap ctrl_c INT

network=192.168.1
ports=(21 22 25 80 110 143 443 445 587 995 993 3306 5985 8080 8081)
tput civis;

for i in $(seq 1 50); do
   echo -ne "\n[+] Enumerando hosts de $network.1/24:"
   echo -ne "\n\n\t[+] Hosts activos:"
   for host in ${hostsactivos[@]}; do
     echo -ne "\n\n\t $host"; 
   done;wait;
   echo -ne "\n\n\t[+] Probando con: $network.$i:"
   timeout 0.5 bash -c "ping -c 1 $network.$i" &>/dev/null && hostsactivos=(${hostsactivos[@]} $network.$i);
   clear;
done;wait;


for host in ${hostsactivos[@]}; do
        echo -e "\n\n[+] Enumerando puertos para el host $host"
        for port in ${ports[@]}; do
          timeout 0.5 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -ne "\n[+] Host $host\t - Port $port - OPEN" &
        done;wait;
done;wait;
tput cnorm

