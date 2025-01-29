#!/usr/bin/python3

import discord
import asyncio
import os
import subprocess
from datetime import datetime


# Configuración del bot
IP_BANS_FILE = "/home/kermit/ip_bans.txt"  # Archivo donde se guardan las IPs baneadas

TOKEN = ""
CHANNEL_ID = 

intents = discord.Intents.default()
client = discord.Client(intents=intents)

# Función para contar IPs bloqueadas por fail2ban
def contar_baneos():
    log_file = "/var/log/fail2ban.log"
    ssh_bans, nextcloud_bans = 0, 0
    ssh_ips, nextcloud_ips = set(), set()

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            if "Ban" in line:
                ip = line.split()[-1]  # Extraer la IP
                guardar_ip_baneada(ip)  # Guardar IP en el archivo

                if "sshd" in line:
                    ssh_bans += 1
                    ssh_ips.add(ip)
                elif "nextcloud" in line:
                    nextcloud_bans += 1
                    nextcloud_ips.add(ip)

    except Exception as e:
        print(f"Error leyendo los logs de fail2ban: {e}")

    return ssh_bans, len(ssh_ips), nextcloud_bans, len(nextcloud_ips)


# Función para guardar IPs baneadas en un archivo sin duplicarlas
def guardar_ip_baneada(ip):
    try:
        if not os.path.exists(IP_BANS_FILE):
            open(IP_BANS_FILE, "w").close()  # Crear el archivo si no existe

        # Leer IPs ya registradas para evitar duplicados
        with open(IP_BANS_FILE, "r") as f:
            ips_registradas = set(f.read().splitlines())

        if ip not in ips_registradas:
            with open(IP_BANS_FILE, "a") as f:
                f.write(ip + "\n")
            print(f"✅ IP {ip} guardada en {IP_BANS_FILE}")

    except Exception as e:
        print(f"❌ Error al guardar la IP en el archivo: {e}")


# Función para contar ataques detectados por iptables
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


# Monitoreo en tiempo real de baneos en fail2ban
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
                        ip = line.split()[-1]  # Extraer la IP
                        guardar_ip_baneada(ip)  # Guardar IP en archivo
                        await channel.send(f"🚨 **Alerta de seguridad:** {line.strip()}")

        except Exception as e:
            print(f"❌ Error leyendo el archivo de logs: {e}")

        await asyncio.sleep(5)


# Reporte diario con estadísticas de ataques
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

        await asyncio.sleep(86400)  # Espera 24 horas


@client.event
async def on_ready():
    print(f"{client.user} está activo y enviando reportes de seguridad.")
    
    await asyncio.sleep(2)  # Pequeña espera para que se cargue bien el bot
    
    channel = client.get_channel(CHANNEL_ID)
    
    if channel is None:
        print("❌ Error: No se encontró el canal. Verifica el ID del canal en Discord.")
    else:
        print(f"✅ Canal encontrado: {channel.name} (ID: {CHANNEL_ID})")
        await channel.send("✅ El bot de monitoreo está funcionando correctamente.")

    asyncio.create_task(monitor_logs())
    asyncio.create_task(enviar_reporte_diario())

client.run(TOKEN)

