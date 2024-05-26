wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_386
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_386.exe
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe

git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries ./ghostpack

wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/impacket_linux_binaries.tar.gz
mkdir impacket
tar -xf impacket_linux_binaries.tar.gz -C impacket
rm impacket_linux_binaries.tar.gz

wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/impacket_windows_binaries.zip
unzip impacket_windows_binaries.zip 
mv dist impacket_ropnop
rm impacket_windows_binaries.zip

wget https://github.com/maaaaz/impacket-examples-windows/releases/download/v0.9.17/impacket-examples-windows-v0.9.17.zip
unzip impacket-examples-windows-v0.9.17.zip -d impacket

wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip SysinternalsSuite.zip -d sysinternals
rm SysinternalsSuite.zip

git clone https://github.com/Flangvik/SharpCollection

wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
unzip netcat-win32-1.11.zip
unzip netcat-win32-1.12.zip
rm netcat-win32-1.11.zip
rm netcat-win32-1.12.zip

git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack
git clone https://github.com/NetSPI/PowerUpSQL
git clone https://github.com/HarmJ0y/Misc-PowerShell
git clone https://github.com/antonioCoco/ConPtyShell
wget https://github.com/antonioCoco/ConPtyShell/releases/download/1.5/ConPtyShell.zip
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1
wget https://github.com/samratashok/nishang/archive/refs/tags/v0.7.6.zip
git clone https://github.com/Kevin-Robertson/Invoke-TheHash
git clone https://github.com/leechristensen/Random
