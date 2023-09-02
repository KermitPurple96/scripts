#!/bin/bash

green="\e[0;32m\033[1m"
end="\033[0m\e[0m"
red="\e[0;31m\033[1m"
blue="\e[0;34m\033[1m"
yellow="\e[0;33m\033[1m"
purple="\e[0;35m\033[1m"
turquoise="\e[0;36m\033[1m"
gray="\e[0;37m\033[1m"
negro="\e[0;30m\033[1m"
fondonegro="\e[0;40m\033[1m"
fondoverde="\e[0;42m\033[1m"
fondoamarillo="\e[0;43m\033[1m"
fondoazul="\e[0;44m\033[1m"
fondopurple="\e[0;46m\033[1m"
fondogris="\e[0;47m\033[1m"

function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        tput cnorm;exit 1
}

#Ctrl+C
trap ctrl_c INT

network=192.168.1
ports=(21 22 23 25 53 80 110 111 123 137 138 139 143 161 389 443 445 465 514 515 587 993 995 1080 1433 1521 3306 3307 3389 5432 5900 59845985 6379 8080 8081 8443 9000 9090 9200 9300 10000 11211 27017 28017 50070 54321 5632 5901)
#ports=(21 22 25 80 110 143 443 445 587 995 993 3306 5985 8080 8081)
tput civis;

for i in $(seq 1 254); do
   echo -ne "\n${blue}[+]${end} Enumerando hosts de ${green}$network.1/24:"
   echo -ne "\n\n\t${green}[+]${end} Hosts activos:"
   for host in ${hostsactivos[@]}; do
     echo -ne "\n\n\t\t ${green}$host${end}"; 
   done;wait;
   echo -ne "\n\n\t${red}[+]${end} Probando con: ${yellow}$network.$i${end}:"
   timeout 0.5 bash -c "ping -c 1 $network.$i" &>/dev/null && hostsactivos=(${hostsactivos[@]} $network.$i);
   clear;
done;wait;


for host in ${hostsactivos[@]}; do
        echo -e "\n\n${purple}[+]${end} Enumerando puertos para el host ${green}$host${end}"
        for port in ${ports[@]}; do
          timeout 0.5 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -ne "\n${blue}[+] ${green}$host${end} - ${red}$port${end} - OPEN" &
        done;wait;
done;wait;
echo -e "\n"
tput cnorm
