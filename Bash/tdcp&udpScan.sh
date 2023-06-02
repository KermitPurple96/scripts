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

HELP="\n${green}[+]${end} $0 <network>/<netmask> <protocol>\n\n\t${blue}[+]${end}$0 172.18.0.1/24 tcp\n\t${blue}[+]${end}$0 192.168.0.1/16 udp\n";

if [ "$#" -ne 2 ] ; then
  echo -e $HELP;
	exit 1;
fi

function ctrl_c(){
  echo -e "\n\n${red}[!]${end} Saliendo...\n"
  tput cnorm;exit 1
}

#Ctrl+C
trap ctrl_c INT

netmask=$(echo $1 | cut -d '/' -f 2)
network=$(echo $1 | cut -d '.' -f 1-3)
net16=$(echo $1 | cut -d '.' -f 1-2)
prot=$2
ports=(21 22 23 25 53 80 88 110 143 443 445 587 995 993 3306 5985 8080 8081)
tput civis;

function scan(){

  if [[ $2 == "16" ]]; then

    for j in $(seq 1 254); do
      for i in $(seq 1 254); do
          echo -ne "\n${blue}[+]${end} Enumerando hosts de ${green}$net16.$j.1/16: por $prot"
          echo -ne "\n\n\t${green}[+]${end} Hosts activos:"
          for host in ${hostsactivos[@]}; do
              echo -ne "\n\n\t\t ${green}$host${end}"; 
          done;wait;
          echo -ne "\n\n\t${red}[+]${end} Probando con: ${yellow}$net16.$j.$i${end}:"
          timeout 0.5 bash -c "ping -c 1 $net16.$j.$i" &>/dev/null && hostsactivos=(${hostsactivos[@]} $net16.$j.$i);
          clear;
      done;wait;


      for host in ${hostsactivos[@]}; do
          echo -e "\n\n${purple}[+]${end} Enumerando puertos para el host ${green}$host${end} por $prot"
          for port in ${ports[@]}; do
              timeout 0.5 bash -c "echo '' > /dev/$prot/$host/$port" 2>/dev/null && echo -ne "\n\t${blue}[+] ${green}$host${end} - ${red}$port${end} - OPEN" &
          done;wait;
      done;wait;
    done;wait;
    tput cnorm; echo -ne "\n"; exit 0
  fi
  
  if [[ $2 == "24" ]]; then

    for i in $(seq 1 254); do
        echo -ne "\n${blue}[+]${end} Enumerando hosts de ${green}$network.1/24: por $prot"
        echo -ne "\n\n\t${green}[+]${end} Hosts activos:"
        for host in ${hostsactivos[@]}; do
            echo -ne "\n\n\t\t ${green}$host${end}"; 
        done;wait;
        echo -ne "\n\n\t${red}[+]${end} Probando con: ${yellow}$network.$i${end}:"
        timeout 0.5 bash -c "ping -c 1 $network.$i" &>/dev/null && hostsactivos=(${hostsactivos[@]} $network.$i);
        clear;
    done;wait;


    for host in ${hostsactivos[@]}; do
        echo -e "\n\n${purple}[+]${end} Enumerando puertos para el host ${green}$host${end} por $prot"
        for port in ${ports[@]}; do
            timeout 0.5 bash -c "echo '' > /dev/$prot/$host/$port" 2>/dev/null && echo -ne "\n\t${blue}[+] ${green}$host${end} - ${red}$port${end} - OPEN" &
        done;wait;
    done;wait;
  tput cnorm; echo -ne "\n"; exit 0
  fi

}

if [[ $2 == "tcp" ]]; then
    scan $network $netmask $net16 $prot
elif [[ $2 == "udp" ]]; then
    scan $network $netmask $net16 $prot
else
  echo -e $HELP;
  exit 1;
fi

echo -ne "\n"; echo 
tput cnorm
