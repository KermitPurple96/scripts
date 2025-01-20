#!/bin/bash

# parses URLs extracted from hakrawler removing unwanted and duplicate domains 
# unlike parseUrls.sh it only leaves single routes
# parseUrls.sh urls.txt target_domain
# example:
# parseUrls.sh urls.txt inlanefreight
# http://blog.inlanefreight.local/
# http://blog.inlanefreight.local/wp-admin/admin-ajax.php
# http://blog.inlanefreight.local/wp-admin/js/password-strength-meter.min.js

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Uso: $0 archivo_de_urls.txt dominio_a_filtrar"
    exit 1
fi

while IFS= read -r line; do
    domain=$(echo "$line" | grep -oP '://([a-zA-Z0-9.-]+)' | head -n 1 | cut -d'/' -f3)
    
    if [[ "$domain" == *"$2"* ]]; then
        clean_url=$(echo "$line" | sed 's/?[^ ]*//')
        echo "$clean_url"
    fi
done < "$1" | sort -u | uniq | sponge "$1"
