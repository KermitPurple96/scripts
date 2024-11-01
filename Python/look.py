#!/usr/bin/python3
import subprocess
import re
import sys

# Función para ejecutar un comando nslookup y devolver la salida
def run_nslookup(query, ip):
    try:
        result = subprocess.run(['nslookup'] + query.split() + [ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error ejecutando nslookup: {e}")
        return None

# Función para extraer subdominios válidos de la salida del nslookup
def extract_subdomains(output):
    subdomains = []
    
    # Extraer cualquier subdominio que aparezca después de 'service ='
    for line in output.splitlines():
        match = re.search(r'service = \d+ \d+ \d+ ([\w.-]+)', line)
        if match:
            subdomain = match.group(1)
            # Filtrar dominios con patrones no deseados y dominios inversos
            if not subdomain.startswith("_ldap._tcp.dc._msdcs.") and not subdomain.endswith("in-addr.arpa") and not re.match(r'^\d+\.\d+\.\d+\.\d+$', subdomain):
                subdomains.append(subdomain)
    
    return subdomains

# Función principal que ejecuta las consultas y realiza las consultas recursivas en los subdominios encontrados
def perform_nslookups(domain, ip, visited):
    queries = [
        domain,
        f"-type=srv _ldap._tcp.dc._msdcs.{domain}",
        f"-q=srv _ldap._tcp.dc._msdcs.{domain}",
        f"-type=srv _gc._tcp.{domain}",
        f"-type=srv _kerberos._tcp.{domain}",
        f"-type=srv _kerberos._udp.{domain}",
        f"-type=srv _kpasswd._tcp.{domain}",
        f"-type=srv _kpasswd._udp.{domain}",
        f"-type=srv _ldap._tcp.{domain}",
        f"-type=srv _ldap._tcp.dc._msdcs.{domain}"
    ]
    
    # Ejecutar todas las consultas de nslookup
    for query in queries:
        output = run_nslookup(query, ip)
        
        # Extraer subdominios válidos del resultado
        subdomains = extract_subdomains(output)
        
        # Mostrar los subdominios encontrados, sin duplicados
        for subdomain in subdomains:
            if subdomain not in visited:
                visited.add(subdomain)  # Añadir al conjunto para evitar duplicados
                print(f"{subdomain}")
                perform_nslookups(subdomain, ip, visited)  # Llamada recursiva para subdominios encontrados

# Ejemplo de uso
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py <dominio> <ip>")
        sys.exit(1)

    domain = sys.argv[1]
    ip = sys.argv[2]
    visited = set()  # Conjunto para evitar duplicados
    perform_nslookups(domain, ip, visited)
