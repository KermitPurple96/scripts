#!/bin/bash
 
IP=$(/usr/sbin/ifconfig | grep ens33 -A1 | grep inet | awk '{print $2}')
if [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "%{F#2495e7} %{F#ffffff}$(/usr/sbin/ifconfig | grep ens33 -A1 | grep inet | awk '{print $2}')%{u-}"
else 
  echo "%{F#2495e7} %{F#ffffff}Disconnected"
fi
