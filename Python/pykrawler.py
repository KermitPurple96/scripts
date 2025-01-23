import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import argparse
import sys
from bs4 import Comment
import httpx
from termcolor import colored


# Almacena las URLs únicas
visited_urls = set()
subdomains_found = set()
output_results = set()


def clean_url(url):
    """
    Elimina cualquier contenido a la derecha de una coma ',' o un punto y coma ';' en la URL.
    """
    return re.split(r"[,;]", url)[0]

def crawl(url, depth, max_depth, inside, headers, subs, base_domain):
    """
    Función recursiva para rastrear URLs en el sitio web.
    """
    if depth > max_depth or url in visited_urls:
        return

    visited_urls.add(url)

    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")

        # Analiza todas las etiquetas <a> para enlaces
        for link in soup.find_all(["a", "area"], href=True):
            href = link["href"]
            full_url = clean_url(urljoin(url, href))
            if should_visit(full_url, base_domain, subs):
                print_result(full_url, "href", url)
                crawl(full_url, depth + 1, max_depth, inside, headers, subs, base_domain)

        # Analiza etiquetas <script>, <link>, <img>, <iframe> y más
        for tag in soup.find_all(["script", "link", "img", "iframe", "source"], src=True):
            src_url = clean_url(urljoin(url, tag.get("src", "")))
            if should_visit(src_url, base_domain, subs):
                print_result(src_url, tag.name, url)

        # Analiza contenido en comentarios HTML
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            find_urls_in_text(comment, url, base_domain, subs)

        # Busca subdominios en metadatos y cabeceras HTTP
        for meta in soup.find_all("meta", content=True):
            meta_url = clean_url(urljoin(url, meta["content"]))
            if should_visit(meta_url, base_domain, subs):
                print_result(meta_url, "meta", url)

        # Busca subdominios en cabeceras HTTP
        for header in ["Location", "Referer", "Content-Location"]:
            if header in response.headers:
                header_url = clean_url(urljoin(url, response.headers[header]))
                if should_visit(header_url, base_domain, subs):
                    print_result(header_url, f"header-{header}", url)

        # Analiza texto plano en la página
        find_urls_in_text(response.text, url, base_domain, subs)

        # Analiza el encabezado "Location" para redirecciones
        if "Location" in response.headers:
            redirect_url = clean_url(urljoin(url, response.headers["Location"]))
            if should_visit(redirect_url, base_domain, subs):
                print_result(redirect_url, "redirect", url)

        # Intenta descargar y analizar sitemap.xml
        if depth == 0:
            sitemap_url = clean_url(urljoin(url, "/sitemap.xml"))
            analyze_sitemap(sitemap_url, headers, base_domain, subs)

    except requests.RequestException as e:
        print(f"Error al acceder a {url}: {e}", file=sys.stderr)

def should_visit(url, base_domain, subs):
    """
    Determina si se debe visitar una URL basada en el dominio y subdominios.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]  # Extraer solo el dominio sin el puerto

    # Verificar que el dominio pertenece al objetivo o sus subdominios
    if subs:
        if domain.endswith(base_domain):
            subdomains_found.add(domain)
            return True
        return False
    else:
        return domain == base_domain

def find_urls_in_text(text, current_url, base_domain, subs):
    """
    Busca URLs en el texto de la respuesta HTTP utilizando expresiones regulares.
    """
    urls = re.findall(r"https?://[\w.-]+(?:/[^\s\"'>]*)?", text)

    for url in urls:
        clean = clean_url(url)
        if should_visit(clean, base_domain, subs):
            print_result(clean, "text", current_url)

    # Extraer subdominios adicionales
    subdomain_candidates = re.findall(r"https?://([\w.-]+)", text)
    for candidate in subdomain_candidates:
        if candidate.endswith(base_domain):
            subdomains_found.add(candidate)

def analyze_sitemap(sitemap_url, headers, base_domain, subs):
    """
    Descarga y analiza un archivo sitemap.xml para encontrar URLs adicionales.
    """
    try:
        response = requests.get(sitemap_url, headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", response.text)
            for url in urls:
                clean = clean_url(url)
                if should_visit(clean, base_domain, subs):
                    print_result(clean, "sitemap", sitemap_url)
    except requests.RequestException as e:
        print(f"Error al analizar sitemap {sitemap_url}: {e}", file=sys.stderr)

def print_result(url, source, found_at):
    """
    Almacena y opcionalmente imprime la URL rastreada.
    """
    if url not in output_results:
        output_results.add(url)
        print(url)

def filter_non_404_urls(urls, headers):
    """
    Filtra las URLs que no devuelven un código de estado 404.
    """
    valid_urls = set()
    with httpx.Client(headers=headers, verify=False) as client:
        for url in urls:
            try:
                response = client.head(url, timeout=10)
                if response.status_code != 404:
                    valid_urls.add(url)
                else:
                    print(colored("404 not found", "red"))
                    print(url)
            except httpx.RequestError as e:
                print(f"Error al verificar URL {url}: {e}", file=sys.stderr)
    return valid_urls

def main():
    parser = argparse.ArgumentParser(description="Python crawler similar to Hakrawler.")
    parser.add_argument("start_url", help="URL inicial para rastrear.")
    parser.add_argument("--max-depth", type=int, default=2, help="Profundidad máxima de rastreo.")
    parser.add_argument("--headers", help="Cabeceras personalizadas en formato 'Clave: Valor;;Clave: Valor'.")
    parser.add_argument("--inside", action="store_true", help="Rastrea solo dentro del dominio.")
    parser.add_argument("--subs", action="store_true", help="Incluye subdominios en el rastreo.")
    parser.add_argument("--outfile", help="Archivo donde guardar los resultados.")
    parser.add_argument("--filter-non-404", action="store_true", help="Filtra URLs que no devuelven 404.")
    args = parser.parse_args()

    # Configuración de cabeceras
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
    if args.headers:
        for header in args.headers.split(";;"):
            key, value = header.split(": ", 1)
            headers[key.strip()] = value.strip()

    # Parsear dominio base
    parsed_url = urlparse(args.start_url)
    base_domain = parsed_url.netloc.split(':')[0]

    # Inicia el rastreo
    crawl(args.start_url, 0, args.max_depth, args.inside, headers, args.subs, base_domain)

    # Filtrar URLs no 404 si se especifica
    if args.filter_non_404:
        global output_results
        output_results = filter_non_404_urls(output_results, headers)

    # Escribir resultados en archivo si se especifica
    if args.outfile:
        with open(args.outfile, "w") as f:
            for url in output_results:
                f.write(url + "\n")

    # Imprime subdominios encontrados
    if args.subs:
        print("\nSubdominios encontrados:")
        for subdomain in subdomains_found:
            print(subdomain)

if __name__ == "__main__":
    main()
