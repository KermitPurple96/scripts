import re
import sys

def parse_urls(input_file, output_file, domain_filter, extensions):
    """
    Procesa un archivo de URLs, filtra por dominio y elimina duplicados.
    Limpia URLs de #, ?, , o ;.
    Filtra por extensiones permitidas y guarda los resultados en un archivo de salida especificado.
    urls.txt generado por https://github.com/KermitPurple96/scripts/blob/main/Python/pykrawler.py
    python parse_urls.py urls.txt filtered_urls.txt example.com .html .js .php
    """
    try:
        # Leer las líneas del archivo de entrada
        with open(input_file, "r") as file:
            lines = file.readlines()
        
        # Procesar y filtrar las URLs
        filtered_urls = set()
        for line in lines:
            # Extraer el dominio usando regex
            match = re.search(r"://([a-zA-Z0-9.-]+)", line)
            if match:
                domain = match.group(1)
                # Comprobar si el dominio coincide con el filtro
                if domain_filter in domain:
                    # Eliminar todo lo que esté después de #, ?, , o ;
                    clean_url = re.split(r"[#?,;]", line.strip())[0]
                    # Comprobar si la URL tiene una extensión permitida
                    if any(clean_url.endswith(ext) for ext in extensions):
                        filtered_urls.add(clean_url)
        
        # Escribir las URLs filtradas y únicas en el archivo de salida
        with open(output_file, "w") as file:
            for url in sorted(filtered_urls):
                file.write(url + "\n")
        
        print(f"[+] URLs procesadas y guardadas en '{output_file}'")
                
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{input_file}'")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Uso: python parse_urls.py archivo_entrada archivo_salida dominio_a_filtrar ext1 [ext2 ... extN]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    domain_filter = sys.argv[3]
    extensions = sys.argv[4:]
    parse_urls(input_file, output_file, domain_filter, extensions)
