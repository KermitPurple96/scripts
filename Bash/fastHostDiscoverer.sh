#!/bin/bash


for port in 21 22 25 80 88 443 445 8080 8081; do
  for i in $(seq 1 254); do 
    proxychains timeout 1 bash -c "echo '' > /dev/tcp/10.241.251.$i/$port" 2>/dev/null && echo "[+] port $port OPEN on host 10.241.251.$i" &
  done; wait
done
