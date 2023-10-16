#!/bin/bash

for i in $(seq 1 255); do
  sleep 1
  bash -c "ping -c 1 192.168.1.$i" &>/dev/null && echo "Host 192.168.1.$i active" &
done;wait
