#!/usr/bin/python3

import discord
import asyncio
import os
import subprocess
from datetime import datetime

IP_BANS_FILE = "/home/kermit/ip_bans.txt"

TOKEN = ""
CHANNEL_ID = 

intents = discord.Intents.default()
client = discord.Client(intents=intents)

def contar_baneos():
    log_file = "/var/log/fail2ban.log"
    ssh_bans, nextcloud_bans = 0, 0
    ssh_ips, nextcloud_ips = set(), set()

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            if "Ban" in line:
                ip = line.split()[-1]
                guardar_ip_baneada(ip)

                if "sshd" in line:
                    ssh_bans += 1
                    ssh_ips.add(ip)
                elif "nextcloud" in line:
                    nextcloud_bans += 1
                    nextcloud_ips.add(ip)

    except Exception as e:
        print(f"Error leyendo los logs de fail2ban: {e}")

    return ssh_bans, len(ssh_ips), nextcloud_bans, len(nextcloud_ips)

def guardar_ip_baneada(ip):
    try:
        if not os.path.exists(IP_BANS_FILE):
            open(IP_BANS_FILE, "w").close()

        with open(IP_BANS_FILE, "r") as f:
            ips_registradas = set(f.read().splitlines())

        if ip not in ips_registradas:
            with open(IP_BANS_FILE, "a") as f:
                f.write(ip + "\n")
            print(f"✅ IP {ip} guardada en {IP_BANS_FILE}")

    except Exception as e:
        print(f"❌ Error al guardar la IP en el archivo: {e}")

def contar_ataques_iptables():
    ports = {"22": 0, "80": 0, "443": 0}
    
    try:
        result = subprocess.run(["sudo", "grep", "DROPPED" , "/var/log/syslog"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            for port in ports.keys():
                if f"DST={port}" in line:
                    ports[port] += 1

    except Exception as e:
        print(f"Error leyendo los logs de iptables: {e}")

    return ports["22"], ports["80"], ports["443"]

async def monitor_logs():
    channel = client.get_channel(CHANNEL_ID)
    if channel is None:
        print("❌ Error: No se encontró el canal para enviar alertas.")
        return

    log_file = "/var/log/fail2ban.log"
    last_position = 0

    while True:
        try:
            with open(log_file, "r") as f:
                if last_position == 0:
                    f.seek(0, os.SEEK_END)
                    last_position = f.tell()

                f.seek(last_position)
                lines = f.readlines()
                last_position = f.tell()

                for line in lines:
                    if "Ban" in line:
                        ip = line.split()[-1]
                        jail = line.split("[")[-1].split("]")[0]

                        if "Restore Ban" in line:
                            icono = "🔄"
                            mensaje = f"**Restore Ban en `{jail}`:** 🔄 La IP `{ip}` ha sido restablecida por Fail2Ban."
                        else:
                            icono = "🚨"
                            mensaje = f"**Alerta de seguridad en `{jail}`:** {icono} La IP `{ip}` ha sido **BANEADA**."
                            
                        await channel.send(f"{icono} {mensaje}")

        except Exception as e:
            print(f"❌ Error leyendo el archivo de logs: {e}")

        await asyncio.sleep(5)

async def enviar_reporte_diario():
    await client.wait_until_ready()
    channel = client.get_channel(CHANNEL_ID)

    if channel is None:
        print("❌ Error: No se encontró el canal para enviar reportes.")
        return

    while not client.is_closed():
        try:
            ssh_bans, ssh_ips, nextcloud_bans, nextcloud_ips = contar_baneos()
            ssh_iptables, http_iptables, https_iptables = contar_ataques_iptables()

            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            mensaje = (
                f"📊 **Reporte de Seguridad - {fecha}** 📊\n\n"
                f"🔹 **Fail2Ban:**\n"
                f"   🔹 SSH (22): {ssh_bans} intentos bloqueados, {ssh_ips} IPs únicas\n"
                f"   🔹 Nextcloud (80, 443): {nextcloud_bans} intentos bloqueados, {nextcloud_ips} IPs únicas\n\n"
                f"🔹 **Iptables (paquetes bloqueados):**\n"
                f"   🔹 SSH (22): {ssh_iptables}\n"
                f"   🔹 HTTP (80): {http_iptables}\n"
                f"   🔹 HTTPS (443): {https_iptables}\n"
            )

            await channel.send(mensaje)
        except Exception as e:
            print(f"❌ Error enviando reporte diario: {e}")
            
        await asyncio.sleep(86400)

@client.event
async def on_ready():
    print(f"{client.user} está activo y enviando reportes de seguridad.")
    await asyncio.sleep(2)
    channel = client.get_channel(CHANNEL_ID)
    
    if channel is None:
        print("❌ Error: No se encontró el canal. Verifica el ID del canal en Discord.")
    else:
        print(f"✅ Canal encontrado: {channel.name} (ID: {CHANNEL_ID})")

    asyncio.create_task(monitor_logs())
    asyncio.create_task(enviar_reporte_diario())

client.run(TOKEN)

