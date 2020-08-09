#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# TALLER VIRTUAL DE CRIPTOGRAFÍA PRÁCTICA
# 8. FIRMAS DIGITALES
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

import random
import os
import hashlib
from base64 import b64encode, b64decode
from datetime import datetime
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

#Se define alfabeto a utilzar en el cifrado
dic = {'A':1,'B':2,'C':3,'D':4,'E':5,'F':6,'G':7,'H':8,
       'I':9,'J':10,'K':11,'L':12,'M':13,'N':14,'Ñ':15,'O':16,
       'P':17,'Q':18,'R':19,'S':20,'T':21,'U':22,'V':23,'W':24,
       'X':25,'Y':26,'Z':27,'0':28,'1':29,'2':30,'3':31,'4':32,
       '5':33,'6':34,'7':35,'8':36,'9':37}


def leer_archivo(nombre):
    """ Función que permite leer el archivo, si el archivo no se encuentra manda mensaje notificando 
        y termina el programa.
        
        Args:
            nombre(str): Nombre del archivo a leer

        Returns:
            datos(str): Datos leidos del archivo
    """
    try:
        f = open(nombre,'rb')
        datos = f.read()
        f.close
        return datos
    except:
        print ("\n\t\t*** No se encontró el archivo '"+nombre+"' :( *** \n")
        exit()

def guardar_archivo(nombre, datos):
    """ Función que permite guardar datos en un archivo, si el archivo no se encuentra manda mensaje notificando 
        y termina el programa.
        
        Args:
            nombre(str): Nombre del archivo a leer
            datos(str): Cadena de datos a ser guardada en archivo
    """
    try:
        f = open(nombre, 'wb')
        f.write(datos)
        f.close()
    except:
        print("\n\t\t*** No se pudo crear el archivo "+nombre+" *** \n")
        exit()


# Función para obtener el hash de un archivo, recibe la función hash a utilizar. Hace uso de la función leer_archivo
# en donde el archivo es el segundo argumento pasado en la linea de comandos. Regresa el hash.
def obtener_hash(nombre_hash, datos):
    h = hashlib.new(nombre_hash)
    h.update(datos)
    return h.digest()


def cifrar(datos, nombre_archivo):
    print("\n\tIngrese la longitud de la clave a utilizar: \n")
    print("\t    a. 128 bits")
    print("\t    b. 192 bits")
    print("\t    c. 256 bits")
    
    key = b''
    try:
        while True:
            op = input("\n\t    Ingrese su opción: ").lower()

            if op == 'a':
                clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                key = obtener_hash("sha256", clave)[:16]
                clave_compartir = "Clave de 128 bits: " + clave.decode('ascii')
                break
            elif op == 'b':
                clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                key = obtener_hash("sha256", clave)[:24]
                clave_compartir = "Clave de 192 bits: " + clave.decode('ascii')
                break
            elif op == 'c':
                clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                key = obtener_hash("sha256", clave)
                clave_compartir = "Clave de 256 bits: " + clave.decode('ascii')
                break
            else:
                print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")        
    except UnicodeEncodeError:
            print("\n\t\t *** Solo se permiten contraseñas con caracteres ASCII ***\n")
            exit()

    #Obtenemos extensión del archivo
    extencion = nombre_archivo.split('.')
    if len(extencion) >= 2:
        extension = '.' + extencion[-1]
    else:
        extension = ''

    nombre_guardado = nombre_archivo + "_cipher_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+extension) #Nombre del archivo cifrado
    
    cipher = AES.new(key, AES.MODE_CBC) #Crea objeto de cifrado CBC, que usa AES como metodo de cifrado
    ct_bytes = cipher.encrypt(pad(datos, AES.block_size)) #Se cifran los datos en formato bytes
    iv = cipher.iv #Recuperamos vector inicial generado

    iv_ct = b64encode(iv+ct_bytes) #Concatena iv con el mensaje cifrado y codifica a base64

    guardar_archivo(nombre_guardado, iv_ct) #Guardamos datos cifrados

    return iv_ct, nombre_guardado, clave_compartir


def descifrar(datos, nombre_archivo):
    while True:
        op = input("\n\tParece que el archivo comprobado está cifrado, ¿Desea descifrarlo? (Y/n): ").lower()

        if op == 'n':
            print("")
            break
        elif op == 'y':
            print("\n\tIngrese la longitud de la clave a utilizar: \n")
            print("\t    a. 128 bits")
            print("\t    b. 192 bits")
            print("\t    c. 256 bits")

            sel = input("\n\t    Ingrese su opción: ").lower()
            while sel < 'a' or sel > 'c':
                print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")   
                sel = input("\n\t    Ingrese su opción: ").lower()

            key = b''
            try:
                if sel == 'a':
                    clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                    key = obtener_hash("sha256", clave)[:16]
                elif sel == 'b':
                    clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                    key = obtener_hash("sha256", clave)[:24]
                elif sel == 'c':
                    clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                    key = obtener_hash("sha256", clave)

            except UnicodeEncodeError:
                print("\n\t *** Solo se permiten contraseñas con caracteres ASCII ***\n")
                exit()

            #Obtenemos extensión del archivo
            nombre_separado = nombre_archivo.split('.')
            if len(nombre_separado) >= 3:
                extension = '.' + nombre_separado[-1]
            else:
                extension = ''

            nombre_guardado = nombre_separado[0] + extension + "_decipher_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+extension) #Nombre del archivo cifrado
            
            iv_ct = b64decode(datos) #Concatena iv con el mensaje cifrado y codifica a base64
            iv = iv_ct[:AES.block_size] #Separamos vector inicial
            ct = iv_ct[AES.block_size:] #Separamos datos cifrados

            cipher = AES.new(key, AES.MODE_CBC, iv) #Crea objeto de cifrado CBC, que usa AES como metodo de cifrado
            try:
                datos_descifrados = unpad(cipher.decrypt(ct), AES.block_size) #Se descifran los datos en formato bytes
            except:
                print("\n\t\t*** Clave inválida, favor de verificar ***\n")
                exit()

            guardar_archivo(nombre_guardado, datos_descifrados) #Guardamos datos cifrados

            print("\n\tNombre del archivo descifrado: \n\n\t\t\t", nombre_guardado, "\n")

            break
        else:
            print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")  


def firmar(hash_datos, nombre_archivo, clave_compartir):
    try:
        n = int(input("\n\tIngrese el valor de n: ")) #producto de multiplicar dos números primos p y q
        d = int(input("\n\tIngrese el valor de d: ")) # Clave privada
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
    M = 0
    for i in hash_datos.hex().upper():
        M += dic[i]

    r = (M**d) % n

    print("\n\tEl valor a compartir para realizar la comprobración de la firma es: ")
    print("\n\t\t\t(r): ({})".format(r))
    print("\n\tEl archivo a compartir es: \n\n\t\t\t", nombre_archivo, "\n")
    if clave_compartir != '':
        print("\tLa clave a compartir para realizar el descifrado del archivo es: \n\n\t\t\t", clave_compartir, "\n")


def verificar(hash_datos_recividos):
    try:
        n = int(input("\n\tIngrese el valor de n: ")) #producto de multiplicar dos números primos p y q
        r = int(input("\n\tIngrese el valor de r: ")) #Valor de r
        e = int(input("\n\tIngrese el valor de e: ")) # Clave pública
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    r1 = (r**e)%n

    #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
    M = 0
    for i in hash_datos_recividos.hex().upper():
        M += dic[i]

    if r1 == M:
        print("\n\t*** La firma es CORRECTA ***\n")
        return True
    else:
        print("\n\t*** La firma No es CORRECTA, el archivo pudo ser modificado ***\n")
        return False


def main():
    print("\n\t\t *°*°*° Firmar con RSA *°*°*°")
    print("\n\n\tSeleccione una opción: \n")
    print("\t   1. Firmar archivo")
    print("\t   2. Verificar firma de archivo: ")

    while True:
        opcion = input("\n\t   Ingrese su opción: ")
        
        if opcion == '1': #Firmar archivo
            os.system("clear")
            print("\n\t\t *°*°*° Firmar archivo *°*°*°")

            nombre_archivo = input("\n\n\tNombre del archivo a firmar: ")
            datos = leer_archivo(nombre_archivo)
            hash_datos = obtener_hash("rmd160", datos) #Calcula hash RMD160 del archivo

            print("\n\tHash del archivo: ", hash_datos.hex())

            clave_compartir = ''
            while True:
                op = input("\n\t¿Desea cifrar el archivo antes de proceder a la firma? Y/n: ").lower()
                if op == 'y':
                    datos_cifrados, nombre_archivo, clave_compartir = cifrar(datos, nombre_archivo)
                    hash_datos = obtener_hash("rmd160", datos_cifrados)
                    print("\n\tNombre del archivo cifrado: ", nombre_archivo)
                    print("\n\tHash del archivo cifrado: ", hash_datos.hex())
                    break
                elif op == 'n':
                    print("\n\tNombre del archivo: ", nombre_archivo)
                    break
                else:
                    print("\n\t\t*** Opción inválida, vuelva a intentar ***\n") 

            firmar(hash_datos, nombre_archivo, clave_compartir)       
            

            exit()
        elif opcion == '2': #Verificar Firma
            os.system("clear")
            print("\n\t\t *°*°*° Verificar Firma de Archivo *°*°*°")

            nombre_archivo = input("\n\n\tNombre del archivo a confirmar la firma: ")
            datos = leer_archivo(nombre_archivo)
            hash_datos = obtener_hash("rmd160", datos) #Calcula hash RMD160 del archivo

            print("\n\tHash del archivo recibido: ", hash_datos.hex())

            firma_valida = verificar(hash_datos)

            if firma_valida == True and "cipher" in nombre_archivo:
                descifrar(datos, nombre_archivo)
                exit()
            else:
                exit()
        else:
            print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")
        

main()
