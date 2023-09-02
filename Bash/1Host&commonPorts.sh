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

host=192.168.122.1
ports=(21 22 25 80 110 143 443 445 587 995 993 3306 5985 8080 8081)
tput civis;


#echo -e "\n\n${purple}[+]${end} Enumerando puertos para el host ${green}$host${end}"
for port in ${ports[@]}; do
  timeout 0.5 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -ne "\n${blue}[+] ${green}$host${end} - ${red}$port${end} - OPEN" &
done;wait;
echo -e "\n"
tput cnorm
