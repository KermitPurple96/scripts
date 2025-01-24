import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import re
from termcolor import colored
import pyxploitdb
import semver  # Asegúrate de tener instalada esta librería para comparar versiones.
import base64
import xmltodict
import signal

def sig_handler(sig, frame):
    print(Fore.YELLOW + "\n\n\t[!] " + Style.RESET_ALL + "Saliendo...\n")
    sys.exit(0)
 
signal.signal(signal.SIGINT, sig_handler)


# Función para comparar versiones
def is_version_lower(v1, v2):
    try:
        return semver.compare(v1, v2) < 0
    except ValueError:
        return False  # Si no puede comparar, se considera que las versiones son incompatibles



def load_payload(method_name):
    """
    Carga el contenido de un archivo externo de payload XML e inserta el método especificado.
    """
    try:
        with open("payload_template.xml", "r") as file:
            xml_payload = file.read()
            return xml_payload.replace("{methodName}", method_name)
    except FileNotFoundError:
        print(colored("[-] Archivo 'payload_template.xml' no encontrado.", "red"))
        sys.exit(1)




def parse_fault_response(response_text):
    """
    Analiza una respuesta de fallo en formato XML.
    Devuelve el código de error y la descripción si existen.
    """
    try:
        parsed_response = xmltodict.parse(response_text)
        fault = parsed_response.get('methodResponse', {}).get('fault', {}).get('value', {}).get('struct', {})
        if fault:
            fault_code = next((int(member['value']['int']) for member in fault['member'] if member['name'] == 'faultCode'), None)
            fault_string = next((member['value']['string'] for member in fault['member'] if member['name'] == 'faultString'), None)
            return fault_code, fault_string
    except Exception as e:
        print(colored(f"[-] Error al parsear la respuesta de fallo: {e}", "red"))
    return None, None


def exploit_xmlrpc(xmlrpc_url):
    """
    Realiza una solicitud a xmlrpc.php para listar los métodos disponibles y los prueba.
    No muestra respuestas con código de error 403 o "Insufficient arguments".
    """
    # Cargar el payload para listar métodos
    list_methods_payload = load_payload("system.listMethods")

    # Encabezados
    headers = {
        "Content-Type": "application/xml",  # Igual que curl
    }

    try:
        print(colored(f"[+] Enviando solicitud a {xmlrpc_url} para listar métodos...", "blue"))
        
        # Solicitud inicial para listar métodos
        response = requests.post(xmlrpc_url, headers=headers, data=list_methods_payload, timeout=10)

        # Verificar el código de estado
        if response.status_code == 200:
            print(colored(f"[+] Métodos disponibles en {xmlrpc_url}:", "green"))

            # Parsear el XML con xmltodict
            try:
                parsed_response = xmltodict.parse(response.text)
                methods = parsed_response['methodResponse']['params']['param']['value']['array']['data']['value']
                method_list = [method['string'] for method in methods]

                # Guardar métodos disponibles en un archivo
                
                
                with open("methods_available.txt", "w") as file:

                    # Probar cada método disponible
                    for method in method_list:
                        # print(colored(f"[+] Probando método: {method}", "yellow"))
                        method_payload = load_payload(method)

                        try:
                            method_response = requests.post(
                                xmlrpc_url, headers=headers, data=method_payload, timeout=10
                            )

                            # Verificar si hay un fallo en la respuesta
                            fault_code, fault_string = parse_fault_response(method_response.text)
                            if fault_code == 403 or (fault_string and "Insufficient arguments" in fault_string):
                                # Ignorar métodos que devuelvan 403 o argumentos insuficientes
                                print(colored(f"[-] {method} responded with 403 status or 'Insufficient arguments'", "red"))
                                continue

                            # Mostrar la respuesta si no es un fallo conocido
                            if method_response.status_code == 200:
                                print(colored(f"[+] Respuesta válida para {method}:", "green"))
                                file.write(method + "\n")

                                #print(method_response.text)
                            else:
                                print(colored(f"[-] Método {method} no devolvió una respuesta significativa.", "red"))

                        except requests.RequestException as e:
                            print(colored(f"[-] Error al probar el método {method}: {e}", "red"))
                print(colored(f"[+] Métodos guardados en 'methods_available.txt'", "green"))
            except Exception as parse_error:
                print(colored(f"[-] Error al parsear el XML: {parse_error}", "red"))
                print(response.text)  # Imprime la respuesta cruda si hay error al parsear

        else:
            print(colored(f"[-] Solicitud fallida a {xmlrpc_url} con código de estado {response.status_code}", "red"))

    except requests.RequestException as e:
        print(colored(f"[-] Error al interactuar con {xmlrpc_url}: {e}", "red"))





def discover_cms(url, themes=set(), plugins=set(), cms_detected=set(), wp_version=None):
    """
    Detecta plugins, temas y funcionalidades relacionadas con WordPress a partir de URLs.
    Si la URL corresponde a xmlrpc.php, se ejecuta exploit_xmlrpc().
    """
    try:
        # Verificar si la URL apunta a xmlrpc.php
        if url.endswith("xmlrpc.php"):
            print(colored(f"[+] Detectado xmlrpc.php en {url}", "green"))
            exploit_xmlrpc(url)
            cms_detected.add("xmlrpc.php")
            return wp_version

        # Realizar solicitud HTTP para analizar el contenido
        response = requests.head(url, timeout=10)
        if response.status_code != 200:
            print(colored(f"[-] URL no válida o inaccesible: {url} (HTTP {response.status_code})", "red"))
            return wp_version

        # Detectar temas en la URL
        if "/wp-content/themes/" in url:
            theme = url.split("/wp-content/themes/")[1].split("/")[0]
            version = re.search(r'[\?&]ver=([\d\.]+)', url)
            version = version.group(1) if version else 'Desconocida'
            themes.add(f"{theme} (Versión: {version})")

        # Detectar plugins en la URL
        elif "/wp-content/plugins/" in url:
            plugin = url.split("/wp-content/plugins/")[1].split("/")[0]
            version = re.search(r'[\?&]ver=([\d\.]+)', url)
            version = version.group(1) if version else 'Desconocida'
            plugins.add(f"{plugin} (Versión: {version})")

        # Detectar WordPress en meta tags (opcional para simplificar)
        if not wp_version and "wp-" in url:
            wp_version = "Desconocida"
            cms_detected.add("WordPress")
            print(colored(f"[+] WordPress detectado en {url}", "green"))

    except requests.RequestException as e:
        print(colored(f"[-] Error al procesar {url}: {e}", "red"))

    return wp_version






def search_plugins_and_themes(plugins, themes, wp_version):
    # Buscar vulnerabilidades para cada plugin
    for plugin in plugins:
        name_version = plugin.split(" (Versión: ")
        plugin_name = name_version[0]
        plugin_version = name_version[1][:-1] if len(name_version) > 1 else 'Desconocida'
        print(colored(f"\nBuscando vulnerabilidades para el plugin {plugin_name} (Versión: {plugin_version})", "yellow"))
        
        # Usando pyxploitdb para buscar vulnerabilidades
        results = pyxploitdb.searchEDB(f"{plugin_name}", platform="all", _print=False, nb_results=3)
        
        # Verificar la estructura de los resultados
        if isinstance(results, list):
            if results:
                for result in results:
                    exploit_id, description, exploit_type, platform, date_published, verified, port, tag_if_any, author, link = result
                    # Comprobar si la vulnerabilidad corresponde a una versión inferior
                    vuln_version = description.split(" ")[-1]  # Suponiendo que la versión está al final de la descripción
                    if is_version_lower(plugin_version, vuln_version):
                        print(colored(f"  {description} \n {link}", "blue"))  # Color azul para versiones inferiores
                    else:
                        print(colored(f"  {description} \n {link}", "red"))
            else:
                print(colored("  No se encontraron vulnerabilidades para este plugin.", "yellow"))
        else:
            print(colored("  Error al obtener resultados de la búsqueda.", "red"))

    # Buscar vulnerabilidades para cada theme
    for theme in themes:
        name_version = theme.split(" (Versión: ")
        theme_name = name_version[0]
        theme_version = name_version[1][:-1] if len(name_version) > 1 else 'Desconocida'
        print(colored(f"\nBuscando vulnerabilidades para el theme {theme_name} (Versión: {theme_version})", "yellow"))
        
        # Usando pyxploitdb para buscar vulnerabilidades
        results = pyxploitdb.searchEDB(f"{theme_name}", platform="all", _print=False, nb_results=3)
        
        # Verificar la estructura de los resultados
        if isinstance(results, list):
            if results:
                for result in results:
                    exploit_id, description, exploit_type, platform, date_published, verified, port, tag_if_any, author, link = result
                    # Comprobar si la vulnerabilidad corresponde a una versión inferior
                    vuln_version = description.split(" ")[-1]  # Suponiendo que la versión está al final de la descripción
                    if is_version_lower(theme_version, vuln_version):
                        print(colored(f"  {description} \n {link}", "blue"))  # Color azul para versiones inferiores
                    else:
                        print(colored(f"  {description} \n {link}", "red"))
            else:
                print(colored("  No se encontraron vulnerabilidades para este theme.", "yellow"))
        else:
            print(colored("  Error al obtener resultados de la búsqueda.", "red"))

    # Buscar vulnerabilidades para WordPress si se detectó la versión
    if wp_version:
        print(colored(f"\nBuscando vulnerabilidades para WordPress (Versión: {wp_version})", "yellow"))
        
        # Realizar búsqueda por versión de WordPress en lugar de por CVE
        search_query = f"WordPress {wp_version}"
        wp_results = pyxploitdb.searchEDB(search_query, platform="webapps", _print=False, nb_results=3)
        
        # Verificar la estructura de los resultados
        if isinstance(wp_results, list):
            if wp_results:
                for wp_result in wp_results:
                    exploit_id, description, exploit_type, platform, date_published, verified, port, tag_if_any, author, link = wp_result
                    # Comprobar si la vulnerabilidad corresponde a una versión inferior
                    vuln_version = description.split(" ")[-1]  # Suponiendo que la versión está al final de la descripción
                    if is_version_lower(wp_version, vuln_version):
                        print(colored(f"  {description} \n {link}", "blue"))  # Color azul para versiones inferiores
                    else:
                        print(colored(f"  {description} \n {link}", "red"))
            else:
                print(colored("  No se encontraron vulnerabilidades para esta versión de WordPress.", "yellow"))
        else:
            print(colored("  Error al obtener resultados de la búsqueda.", "red"))




if __name__ == "__main__":
    # Verificar si se proporcionó una URL como argumento
    if len(sys.argv) < 2:
        print("Uso: python discover_cms.py <archivo_de_urls>")
        sys.exit(1)

    file_path = sys.argv[1]

    with open(file_path, "r") as file:
        urls = file.readlines()

    all_discovered_paths = set()
    detected_themes = set()
    detected_plugins = set()
    cms_detected = set()
    wp_version = None

    for target_url in urls:
        target_url = target_url.strip()
        
        wp_version = discover_cms(target_url, detected_themes, detected_plugins, cms_detected, wp_version)

    # Mostrar resultados al finalizar
    if "WordPress" in cms_detected:
        print(colored(f"\n[+] WordPress detectado (Versión: {wp_version})", "green"))


    if detected_themes:
        print("\nThemes detectados:")
        for theme in sorted(detected_themes):
            print(theme)

    if detected_plugins:
        print("\nPlugins detectados:")
        for plugin in sorted(detected_plugins):
            print(plugin)

    # Buscar vulnerabilidades en los plugins, themes y WordPress
    search_plugins_and_themes(detected_plugins, detected_themes, wp_version)
