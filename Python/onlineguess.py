#!/usr/bin/python3
import socket
import threading
 
secreto = 33
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("192.168.1.76", 5555))
s.listen()
 
 
def handle_client(clientS):
 
    clientS.send(b"Adivina el numero secreto! \n")
    contador = 0
 
    while True:
        clientS.send(b"Prueba un numero: \n")
 
        num = int(clientS.recv(1024))
 
        contador += 1
 
        if num >= 0 and num <= 1000:
            if num == secreto:
                clientS.send(b"Exito! \n")
                clientS.close()
                break
 
 
            elif num>secreto:
                clientS.send(b"El numero es mayor que el secreto. \n")
            else:
                clientS.send(b"El numero es menor que el secreto. \n")
 
            #cont = contador.to_bytes(2, 'little', signed=False)
            #clientS.send(b"Nº de intentos: \n")
            #clientS.send(contador)
 
 
 
while True:
 
 
    (clientS, clientA) = s.accept();
    client_handler = threading.Thread(target=handle_client, args=(clientS,))
    client_handler.start()
    print(clientA)
 
 
 
#if __name__ == "__main__":
 
    #while True:
        #main()
