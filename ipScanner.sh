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
 
 
tput civis
trap ctrl_c INT
 
function ctrl_c(){
  echo -en "\n${red}[!]${end} Saliendo... \n"
  tput cnorm; exit 1
}
 
 
ttl="$(ping -c 1 $1 | grep ttl | tr '=' ' ' | awk '{print $8}')"
ping -c 1 $1 > /dev/null 2>&1
echo -e "───────────────────────────────────────────"
if [ $? = "1" ]; then
  echo -e "\t${red}[!]${end} Host ${red}$1${end} inactivo"
  tput cnorm; exit 1
else
  echo -e "\t${green}[+]${end} Host ${green}$1${end} activo"
fi
if [[ $ttl -le 64 ]]; then
  echo -e "\n\t${blue}[+]${end} Sistema ${blue}Linux ${end}"
fi
if [[ $ttl -le 128 && $ttl -gt 64 ]]; then
  echo -e "\n\t${green}[+]${end} Sistema ${green}Windows ${end}"
fi
echo -e "───────────────────────────────────────────"
echo -e "\t${green}[+]${end} Escaneando puertos..."
nmapeo="$(nmap -p- --open -T5 -v -n -Pn 127.0.0.1;wait; > /dev/null 2>&1;)"
ports="$(echo $nmapeo | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
ip_address="$(echo $nmapeo | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
echo $ports
echo $ip_address
tput cnorm; exit 0
