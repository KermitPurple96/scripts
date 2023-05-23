#!/bin/bash

function ctrl_c(){
  echo -e "\n\n [!] Leaving...\n"
  tput cnorm; exit 1
}

#Ctrl+C
trap ctrl_c INT
tput civis

#Main Function

host_scan () {
  network=$1
  for i in $(seq 2 254); do
    (
      timeout 1 bash -c "ping -c 1 ${network}.$i" &>/dev/null
      if [ $? -eq 0 ]; then
        echo "[+] Host ${network}.$i - ACTIVE"
        
        # TCP port scanning
        for port in $(seq 1 65535); do
          timeout 1 bash -c "echo '' > /dev/tcp/${network}.$i/$port" &>/dev/null
          if [ $? -eq 0 ]; then
            echo "[+] Host ${network}.$i ACTIVE & TCP PORT $port OPEN"
          fi
        done
        
        # UDP port scanning
        for port in $(seq 1 65535); do
          timeout 1 bash -c "echo '' > /dev/udp/${network}.$i/$port" &>/dev/null
          if [ $? -eq 0 ]; then
            echo "[+] Host ${network}.$i ACTIVE & UDP PORT $port OPEN"
          fi
        done
        
      fi
    ) &
  done
  wait
}

tput cnorm

main() {
  bash -c "ip a"
  echo -n "Enter the network like this (e.g. 10.10.0): "
  read network
  host_scan $network
}
main
