#!/bin/bash

if [ -z "$1" ]; then
  echo "Uso: $0 <archivo_de_ips>"
  exit 1
fi

while IFS= read -r ip; do
  formatted_ip=$(echo "$ip" | tr '.' '_')
  echo "Escaneando IP: $ip"
  nmap -sS --open -p- "$ip" -n -Pn -oG "nmap_${formatted_ip}.txt"
done <"$1"
