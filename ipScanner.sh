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

helpPanel(){
  echo -e "\n\t${green}[+]${end} Parametro ${blue}-i${end} para especificar la ip target"
  echo -e "\n\t${green}[+]${end} Parametro ${blue}-d${end} para especificar el nombre de dominio"
  echo -e "\n\t${green}[+]${end} Ej: ${blue}ipscanner.sh -i ${red}10.10.11.112${end}${blue} -d${end} ${red}stacked.htb${end}\n"
  tput cnorm; exit 0

}
declare -i counter=0; while getopts "i:d:h:" arg; do
    case $arg in
      i) ip_target=$OPTARG; let counter+=1;;
      d) dominio=$OPTARG; let counter+=1;;
      h) helpPanel;;
    esac
done
  
if [ $counter -eq 0 ]; then
  helpPanel
else
  ttl="$(ping -c 1 $ip_target | grep ttl | tr '=' ' ' | awk '{print $8}')"
  ping -c 1 $ip_target > /dev/null 2>&1
  echo -e "───────────────────────────────────────────"
  if [ $? = "1" ]; then
    echo -e "\t${red}[!]${end} Host ${red}$ip_target${end} inactivo"
    tput cnorm; exit 1
  else
    echo -e "\t${green}[+]${end} Host ${green}$ip_target${end} activo"
  fi
  if [[ $ttl -le 64 ]]; then
    echo -e "\n\t${blue}[+]${end} Sistema ${blue}Linux ${end}"
  fi
  if [[ $ttl -le 128 && $ttl -gt 64 ]]; then
    echo -e "\n\t${green}[+]${end} Sistema ${green}Windows ${end}"
  fi
  echo -e "───────────────────────────────────────────"
  echo -e "\t${green}[+]${end} Escaneando puertos..."
  nmap -p1-500 --open -T5 -v -n -Pn $ip_target -oG nmapeo > /dev/null 2>&1
  ports="$(cat nmapeo | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
  echo -e "\n\t${green}[+]${end} Puertos: ${red}$ports${end}"
  echo -e "───────────────────────────────────────────"
  if [[ "$ports" == *"80"* ]]; then
    echo -e "\t${green}[+]${end} Analizando tecnologías web...\n"
    whatweb $ip_target
  else
    echo -e "\t${red}[-]${end} Sin servicio web"
  fi
  echo -e "───────────────────────────────────────────"
  echo -e "\t${green}[+]${end} Analizando puertos...\n"
  nmap -sCV -p$ports $ip_target -oN puertos > /dev/null 2>&1
  echo -e "\t$(bat puertos -l java | grep 'PORT' -A 50 | grep -vE "Service|#")"
  echo -e "\n"
  echo -e "───────────────────────────────────────────"
  echo -e "\t${green}[+]${end} Buscando subdominos...\n"
  echo "# Host addresses" > /etc/hosts
  echo "#" >> /etc/hosts
  echo "127.0.0.1  localhost" >> /etc/hosts
  echo "127.0.1.1  parrot" >> /etc/hosts
  echo -ne "\n\n" >> /etc/hosts
  echo -ne "$ip_target  $dominio">> /etc/hosts
  echo -ne "\n" >> /etc/hosts
  echo "::1        localhost ip6-localhost ip6-loopback" >> /etc/hosts
  echo "ff02::1    ip6-allnodes" >> /etc/hosts
  echo "ff02::2    ip6-allrouters" >> /etc/hosts

  gobuster -q vhost -u "http://$dominio" -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 -r > subdomains
  echo -e "\t${red}$(while read line; do echo \t$line | awk '{print $2}';done < subdomains)${end}"
  tput cnorm; exit 0
fi
