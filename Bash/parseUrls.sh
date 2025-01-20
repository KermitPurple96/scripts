#!/bin/bash

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
done < "$1" | sort -u | sponge "$1"
