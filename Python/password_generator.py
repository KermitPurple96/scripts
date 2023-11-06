#!/usr/bin/python3

import itertools
from pwn import *

# Palabra base
palabra_base = "camion"

def def_handler(sig, frame):
    log.failure("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


# Caracteres de reemplazo
reemplazos = {
    'a': ['a', 'A', '@', '4'],
    'e': ['e', 'E', '3'],
    'i': ['i', 'I', '1'],
    'o': ['o', 'O', '0'],
    's': ['s', 'S', '$', '5']
}

# Separadores
separadores = ['.', '-', '_']

# Generar contraseñas
contraseñas = []

for letra in palabra_base:
    if letra in reemplazos:
        contraseñas.append(reemplazos[letra])
    else:
        contraseñas.append([letra])

# Calcular todas las combinaciones
combinaciones = [''.join(i) for i in itertools.product(*contraseñas)]

p2 = log.progress("Generando contraseñas...")

# Generar todas las posibilidades con números y separadores
combinaciones_con_numeros_y_separadores = []
for combinacion in combinaciones:
    for numero in range(1, 1000):
        for separador in separadores:
            # Generar todas las posibilidades de mayúsculas para cada letra
            for i in range(2 ** len(combinacion)):
                variacion = ''
                for j, letra in enumerate(combinacion):
                    if i & (1 << j):
                        if letra.isalpha() and letra.islower():
                            variacion += letra.upper()
                        else:
                            variacion += letra
                    else:
                        variacion += letra
                combinaciones_con_numeros_y_separadores.append(variacion + separador + str(numero))

    p2.status(f"{len(combinaciones_con_numeros_y_separadores)}")

# Guardar las contraseñas en un archivo
with open('diccionario.txt', 'w') as archivo:
    for contraseña in combinaciones_con_numeros_y_separadores:
        archivo.write(contraseña + '\n')

p1 = log.progress("Finish")
p1.success(f'Se generó un diccionario con {len(combinaciones_con_numeros_y_separadores)} contraseñas.')
