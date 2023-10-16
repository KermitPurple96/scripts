#!/bin/bash


for port in 21 22 23 25 53 80 88 110 123 161 443 445 636 3128 3306 3389 8080 8081 5985; do
  for i in $(seq 1 254); do 
    proxychains timeout 1 bash -c "echo '' > /dev/tcp/10.241.251.$i/$port" 2>/dev/null && echo "[+] port $port OPEN on host 10.241.251.$i" &
  done; wait
done
