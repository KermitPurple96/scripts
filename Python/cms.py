import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import re
from termcolor import colored
import pyxploitdb
import semver  # Asegúrate de tener instalada esta librería para comparar versiones.
import base64

from wordpress_xmlrpc import Client, AnonymousMethod
from wordpress_xmlrpc.methods.users import GetUsersBlogs
from wordpress_xmlrpc.methods.posts import GetPosts

# Función para comparar versiones
def is_version_lower(v1, v2):
    try:
        return semver.compare(v1, v2) < 0
    except ValueError:
        return False  # Si no puede comparar, se considera que las versiones son incompatibles



class ListMethods(AnonymousMethod):
    """
    Clase para invocar el método system.listMethods de manera anónima.
    """
    method_name = "system.listMethods"
    method_args = ()


def exploit_xmlrpc(xmlrpc_url):
    """
    Intenta enumerar los métodos disponibles en xmlrpc.php usando un método anónimo.
    """
    try:
        # Crear cliente XML-RPC sin autenticación
        client = Client(xmlrpc_url, '', '')

        # Llamar al método system.listMethods
        methods = client.call(ListMethods())

        print(colored(f"[+] Métodos disponibles en {xmlrpc_url}:", "green"))
        for method in methods:
            print(f"- {method}")
    except Exception as e:
        print(colored(f"[-] Error al interactuar con {xmlrpc_url}: {e}", "red"))




def discover_cms(url, discovered_paths=set(), themes=set(), plugins=set(), cms_detected=set(), wp_version=None):
    """
    Detecta CMS, temas, plugins y funcionalidades relacionadas con WordPress.
    """
    try:
        # Realizar una solicitud HTTP a la URL proporcionada
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        html_content = response.text

        # Analizar el contenido HTML
        soup = BeautifulSoup(html_content, 'html.parser')

        # Buscar archivos CSS y JS que puedan indicar temas o plugins, y extraer versiones
        for script in soup.find_all(['link', 'script'], src=True):
            href = script.get('src') or script.get('href')
            full_href = urljoin(url, href)

            # Detectar temas en archivos CSS
            if "/wp-content/themes/" in full_href:
                theme = full_href.split("/wp-content/themes/")[1].split("/")[0]
                version = re.search(r'[\?&]ver=([\d\.]+)', full_href)
                version = version.group(1) if version else 'Desconocida'
                themes.add(f"{theme} (Versión: {version})")

            # Detectar plugins en archivos CSS o JS
            elif "/wp-content/plugins/" in full_href:
                plugin = full_href.split("/wp-content/plugins/")[1].split("/")[0]
                version = re.search(r'[\?&]ver=([\d\.]+)', full_href)
                version = version.group(1) if version else 'Desconocida'
                plugins.add(f"{plugin} (Versión: {version})")

        # Buscar la versión de WordPress en el código fuente
        if not wp_version:
            meta_tag = soup.find('meta', attrs={'name': 'generator', 'content': lambda c: c and 'WordPress' in c})
            if meta_tag:
                wp_version = meta_tag['content'].split(' ')[1]
                cms_detected.add(f"WordPress (Versión: {wp_version})")

        # Verificar si se detectó WordPress sin versión
        if soup.find('meta', attrs={'name': 'generator', 'content': lambda c: c and 'WordPress' in c}):
            cms_detected.add("WordPress")

        # Verificar si el archivo xmlrpc.php está presente y habilitado
        xmlrpc_url = urljoin(url, "xmlrpc.php")
        if "xmlrpc.php" not in cms_detected:
            try:
                # Intentar explotar xmlrpc.php con métodos anónimos
                exploit_xmlrpc(xmlrpc_url)
                cms_detected.add("xmlrpc.php")
                discovered_paths.add(xmlrpc_url)
                print(colored(f"[+] xmlrpc.php detectado en {xmlrpc_url}", "green"))
            except Exception as e:
                print(colored(f"[-] No se pudo interactuar con {xmlrpc_url}: {e}", "red"))
    except requests.exceptions.RequestException as e:
        print(f"Error al procesar {url}: {e}", file=sys.stderr)

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




def exploit_xmlrpc(xmlrpc_url, username=None, password=None):
    """
    Explota el archivo xmlrpc.php utilizando la biblioteca python-wordpress-xmlrpc.
    
    Args:
        xmlrpc_url (str): URL del archivo xmlrpc.php.
        username (str, optional): Nombre de usuario para autenticación. Por defecto es None.
        password (str, optional): Contraseña para autenticación. Por defecto es None.
    
    Returns:
        None
    """
    print(colored(f"\n[+] Intentando explotar {xmlrpc_url}", "yellow"))

    try:
        # Crear un cliente para interactuar con xmlrpc.php
        client = Client(xmlrpc_url, username, password) if username and password else Client(xmlrpc_url)

        # Enumerar blogs disponibles
        print(colored("[+] Enumerando blogs disponibles:", "cyan"))
        blogs = client.call(GetUsersBlogs())
        for blog in blogs:
            print(f"  - Blog: {blog['blogName']} ({blog['xmlrpc']})")

        # Si se proporciona usuario/contraseña, intentar enumerar posts
        if username and password:
            print(colored("\n[+] Enumerando publicaciones disponibles:", "cyan"))
            posts = client.call(GetPosts())
            for post in posts[:5]:  # Limitar a los primeros 5 resultados
                print(f"  - {post.title}: {post.link}")

    except Exception as e:
        print(colored(f"[-] Fallo al interactuar con {xmlrpc_url}: {e}", "red"))



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
        print(f"Procesando URL: {target_url}")
        wp_version = discover_cms(target_url, all_discovered_paths, detected_themes, detected_plugins, cms_detected, wp_version)

    # Mostrar resultados al finalizar
    if "WordPress" in cms_detected:
        print(colored(f"\n[+] WordPress detectado (Versión: {wp_version})", "green"))

    print("\nRutas descubiertas:")
    for path in sorted(all_discovered_paths):
        print(path)

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
