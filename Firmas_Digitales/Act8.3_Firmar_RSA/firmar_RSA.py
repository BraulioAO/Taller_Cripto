#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# TALLER VIRTUAL DE CRIPTOGRAFÍA PRÁCTICA
# 8. FIRMAS DIGITALES
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

import os
import hashlib
from base64 import b64encode, b64decode
from datetime import datetime
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

#Se define alfabeto para obtener equivalente numérico de funciones Hash.
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
            datos(bytes): Datos leidos del archivo como tipo de datos bytes
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
            datos(bytes): Cadena de datos de tipo bytes a ser guardada en archivo
    """
    try:
        f = open(nombre, 'wb')
        f.write(datos)
        f.close()
    except:
        print("\n\t\t*** No se pudo crear el archivo "+nombre+" *** \n")
        exit()

def obtener_hash(nombre_hash, datos):
    """ Obtiene el valor hash de una entrada de datos tipo bytes.

        Args:
            nombre_hash(str): Nombre de la función hash a utilizar
            datos(bytes): Datos a los cuales calcular su valor hash

        Returns:
            bytes: valor hash

    """
    h = hashlib.new(nombre_hash) #Se crea un objeto hash
    h.update(datos) #Calcula valor hash de los datos de entrada
    return h.digest() #Devuelve valor hash en forma de bytes.

def cifrar(datos, nombre_archivo):
    """ Función para el cifrado de datos en formato bytes mediante AES en modo CBC, 
        con clave de 128, 192 y 256 bits. El vector inicial (IV) es generado 
        aleatoriamente por el algoritmo de cifrado.

        Args:
            datos(bytes): Datos a cifrar
            nombre_archivo(str): Nombre del archivo donde guardar los datos cifrados.

        Returns:
            iv_ct(bytes): Vector inicial concatenado a los datos cifrados codificado en base64.
            nombre_guardado(str): Nombre del archivo donde se guardó los datos cifrados (iv_ct).
            clave_compartir(str): Cadena "Clave de nnn bits: <<clave>>", con la clave de cifrado.
    """
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
                key = obtener_hash("sha256", clave)[:16] #Obtiene valor hash sha256 (256 bits) de la clave y toma los primeros 128 bits
                clave_compartir = "Clave de 128 bits: " + clave.decode('ascii')
                break
            elif op == 'b':
                clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                key = obtener_hash("sha256", clave)[:24] #Obtiene valor hash sha256 (256 bits) de la clave y toma los primeros 192 bits
                clave_compartir = "Clave de 192 bits: " + clave.decode('ascii')
                break
            elif op == 'c':
                clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                key = obtener_hash("sha256", clave) #Obtiene valor hash sha256 (256 bits) de la clave y toma los 256 bits.
                clave_compartir = "Clave de 256 bits: " + clave.decode('ascii')
                break
            else:
                print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")        
    except UnicodeEncodeError:
            print("\n\t\t *** Solo se permiten contraseñas con caracteres ASCII ***\n")
            exit()

    #Obtenemos extensión del archivo
    extencion = nombre_archivo.split('.') #Separa nombre del archivo mediante el indicador '.'
    if len(extencion) >= 2:
        extension = '.' + extencion[-1]
    else:
        extension = ''

    nombre_guardado = nombre_archivo + "_cipher_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+extension) #Nombre del archivo con los datos cifrados
    
    cipher = AES.new(key, AES.MODE_CBC) #Crea objeto de cifrado CBC, que usa AES como metodo de cifrado
    ct_bytes = cipher.encrypt(pad(datos, AES.block_size)) #Se cifran los datos en formato bytes
    iv = cipher.iv #Recuperamos vector inicial generado

    iv_ct = b64encode(iv+ct_bytes) #Concatena iv con el mensaje cifrado y codifica a base64

    guardar_archivo(nombre_guardado, iv_ct) #Guardamos datos cifrados

    return iv_ct, nombre_guardado, clave_compartir

def descifrar(datos, nombre_archivo):
    """ Función para el descifrado de datos cifrados en formato bytes mediante AES en modo CBC, 
        con clave de 128, 192 y 256 bits. El vector inicial (IV) es recuperado de los primeros
        16 bytes de los datos cifrados. 

        Los datos descifrados se guardan en un archivo.

        Args:
            datos(bytes): Datos a descifrar. Los primeros 16 bytes deben ser el vector inicial (IV)
            nombre_archivo(str): Nombre del archivo con los datos cifrados
    """
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
                    key = obtener_hash("sha256", clave)[:16] #Obtiene valor hash sha256 (256 bits) de la clave y toma los primeros 128 bits
                elif sel == 'b':
                    clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                    key = obtener_hash("sha256", clave)[:24] #Obtiene valor hash sha256 (256 bits) de la clave y toma los primeros 192 bits
                elif sel == 'c':
                    clave = input("\n\tIngrese la clave a utilizar: ").encode('ascii')
                    key = obtener_hash("sha256", clave) #Obtiene valor hash sha256 (256 bits) de la clave y toma los 256 bits.

            except UnicodeEncodeError:
                print("\n\t *** Solo se permiten contraseñas con caracteres ASCII ***\n")
                exit()

            #Obtenemos extensión del archivo
            nombre_separado = nombre_archivo.split('.')
            if len(nombre_separado) >= 3:
                extension = '.' + nombre_separado[-1]
            else:
                extension = ''

            nombre_guardado = nombre_separado[0] + extension + "_decipher_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+extension) #Nombre del archivo donde guardar los datos descifrados
            
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
    """ Función para la creación de la firma digital con RSA

        Args:
            hash_datos(bytes): hash de los datos del archivo a firmar
            nombre_archivo(str): Nombre del archivo a firmar
            clave_compartir(str): Cadena "Clave de nnn bits: <<clave>>", con la clave de cifrado, en caso de estar cifrado.
    """
    try:
        n = int(input("\n\tIngrese el valor de n: ")) #producto de multiplicar dos números primos p y q
        d = int(input("\n\tIngrese el valor de d: ")) # Clave privada
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
    M = 0 # h(M)
    for i in hash_datos.hex().upper():
        M += dic[i]

    r = (M**d) % n #Valor r = (h(M)^d) mod n

    print("\n\tEl valor a compartir para realizar la comprobración de la firma es: ")
    print("\n\t\t\t(r): ({})".format(r))
    print("\n\tEl archivo a compartir es: \n\n\t\t\t", nombre_archivo, "\n")
    if clave_compartir != '':
        print("\tLa clave a compartir para realizar el descifrado del archivo es: \n\n\t\t\t", clave_compartir, "\n")

def verificar(hash_datos_recividos):
    """ Función para verificar la firma digital creada con El Gamal.

        Args:
            hash_datos_recividos(bytes): hash de los datos del archivo a verificar.
    
        Returns:
            bool: Regresa True si la firma es correcta, sino False.
    """
    try:
        n = int(input("\n\tIngrese el valor de n: ")) #producto de multiplicar dos números primos p y q
        r = int(input("\n\tIngrese el valor de r: ")) #Valor de r
        e = int(input("\n\tIngrese el valor de e: ")) # Clave pública
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    r1 = (r**e)%n #Valor r1 = (r^e) mod n, recupera equivalente nuḿerico del hash

    #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
    M = 0 #h(M)
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
        

        else: #Se ingresó opción inválida, volver a intentar
            print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")
        

main()
