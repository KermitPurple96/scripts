#!/bin/bash

# parses URLs extracted from hakrawler removing unwanted and duplicate domains
# parseUrls.sh urls.txt domain
# result example:
# http://blog.inlanefreight.local/?page_id=2
# http://blog.inlanefreight.local/?page_id=2#respond
# http://blog.inlanefreight.local/wp-admin/admin-ajax.php?action=wpdAddSubscription
# http://blog.inlanefreight.local/wp-admin/js/password-strength-meter.min.js?ver=5.8

# Verificar que se pasaron los argumentos necesarios
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Uso: $0 archivo_de_urls.txt dominio_a_filtrar"
    exit 1
fi

# Filtrar URLs y extraer el dominio
while IFS= read -r line; do
    # Extraer el primer dominio entre // y /
    domain=$(echo "$line" | grep -oP '://([a-zA-Z0-9.-]+)' | head -n 1 | cut -d'/' -f3)
    
    # Comprobar si el dominio contiene el valor pasado como argumento
    if [[ "$domain" == *"$2"* ]]; then
        echo "$line"
    fi
done < "$1" | sort -u | uniq | sponge "$1"
