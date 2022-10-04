AP=$(/usr/sbin/route | grep default | awk '{print $2}')
if [[ "$AP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "%{F#2495e7}泌 %{F#ffffff}$(/usr/sbin/route | grep default | awk '{print $2}')%{u-}"
else 
  echo "%{F#2495e7}泌 %{F#ffffff}Disconnected"
fi
