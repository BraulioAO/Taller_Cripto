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

#Se define el inverso del alfabeto
dicI = {1:'A',2:'B',3:'C',4:'D',5:'E',6:'F',7:'G',8:'H',
        9:'I',10:'J',11:'K',12:'L',13:'M',14:'N',15:'Ñ',16:'O',
        17:'P',18:'Q',19:'R',20:'S',21:'T',22:'U',23:'V',24:'W',
        25:'X',26:'Y',27:'Z',28:'0',29:'1',30:'2',31:'3',32:'4',
        33:'5',34:'6',35:'7',36:'8',37:'9'}

def mcd(a, b):
    """ Calcula el máximo común divisor de dos números mediante el
        algoritmo de Euclides
    """
    if b == 0: #Caso base, el residuo es cero
        return a

    #Mientras el residuo no sea cero, se llama recursivamente
    return mcd(b, a%b)

def egcdinv(a,b):
    """ Se utiliza el algoritmo extendido de euclides para calcular el 
        inverso módulo m de e*d --- 1 mod phi (--- es congruente)
    """
    g = [b,a]
    y = []
    u = [1,0]
    v = [0,1]
    while g[-1] != 0:
        y.append(g[-2]//g[-1])
        g.append(g[-2]-(y[-1]*g[-1]))
        u.append(u[-2]-(y[-1]*u[-1]))
        v.append(v[-2]-(y[-1]*v[-1]))

    if v[-2] < 0:
        return v[-2] + b
    else:
        return v[-2]

def es_primo_mayor_101(p):
    """ Comprueba que p sea un numero primo mayor que 101, mediante la 
        operación módulo. Si "p mod n" es cero, significa que p es divisible 
        entre n (101 < n < p), por lo que ya no es primo, sino se sigue comprobando.
    """
    if p <= 101:
        print("\n\t\t***El valor ingresado debe ser un número primo mayor a 101***\n")
        exit()

    for n in range(2,p):
        if not p%n: #Si el residuo es cero, no es primo.
            print("\n\t\t***El valor {} no es primo***\n".format(p))
            exit()

def menor(n1,n2):
    """ Comprueba que 'n1' es menor que 'n2', sino termina programa. """
    if n1 >= n2:
        print("\n\t\t***El número ingresado debe ser menor a {}***\n".format(n2))
        exit()

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
        p = int(input("\n\tIngrese el valor de p: ")) #Número primo
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.

        a = int(input("\n\tIngrese el valor de α: ")) #Número aleatorio menor que P
        menor(a,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        l = int(input("\n\tIngrese el valor de λ: ")) #Clave privada
        menor(l,p) #Comprueba que la clave sea menor que p, sino termina programa.
        es_primo_mayor_101(l) #Comprueba que sea primo mayor a 101, sino termina programa.

        print("\n\t*°*°*° Valor de H *°*°*°\n")
        print("\t    I. Ingresar el valor de H")
        print("\t    A. Generar aleatoriamente")

        phi_p = p-1
        h=0
        while True:
            op = input("\n\t    Ingrese su opción: ").lower()
            if op == 'i':
                while True:
                    h = int(input("\n\tIngrese el valor de H: "))
                    if mcd(h, phi_p) != 1:
                        print("\n\t\t*** mcd(H,ϕp) no es igual a 1, intente con otro valor de H ***")
                        continue
                    if h >= p:
                        print("\n\t\t*** H debe ser menor a P, intente con otro valor de H ***")
                    else:
                        break
                break
            elif op == 'a':
                while mcd(h,phi_p) != 1:
                    h = random.randint(1,p) #Generamos clave privada aleatoria
                print("\n\tValor de H: ", h)
                break
            else:
                print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")        


        M = 0
        for i in hash_datos.hex().upper():
            M += dic[i]

        h_inv = egcdinv(h, phi_p)
        r = (a**h) %p
        s = ((M - l*r) * h_inv) % phi_p



        print("\n\tValor inv({}, {}) = {}".format(h,phi_p,h_inv))
        print("\n\tLos valores a compartir para realizar la comprobración de la firma son: ")
        print("\n\t\t\t(r, s): ({}, {})".format(r,s))
        print("\n\tEl archivo a compartir es: \n\n\t\t\t", nombre_archivo, "\n")
        if clave_compartir != '':
            print("\tLa clave a compartir para realizar el descifrado del archivo es: \n\n\t\t\t", clave_compartir, "\n")


    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

def verificar(hash_datos_recividos):
    try:
        p = int(input("\n\tIngrese el valor de p: ")) #Número primo
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.

        r = int(input("\n\tIngrese el valor de r: ")) #Valor r
        menor(r,p) #Comprueba que 'r' sea menor que 'p', sino termina programa

        s = int(input("\n\tIngrese el valor de s: ")) #Valor s
        menor(s,p-1) #Comprueba que 's' sea menor que 'ϕp', sino termina programa

        a = int(input("\n\tIngrese el valor de α: ")) #Número aleatorio menor que P
        menor(a,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        b = int(input("\n\tIngrese el valor de β: ")) #Clave pública
        menor(b,p) #Comprueba que 'a' sea menor que 'p', sino termina programa
    
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    N1 = (r**s) % p
    N2 = (b**r) % p
    k1 = (N1*N2) % p

    M = 0
    for i in hash_datos_recividos.hex().upper():
        M += dic[i]

    k2 = (a**M) % p

    if k1 == k2:
        print("\n\t*** La firma es CORRECTA ***\n")
        return True
    else:
        print("\n\t*** La firma No es CORRECTA, el archivo pudo ser modificado ***\n")
        return False


def main():
    print("\n\t\t *°*°*° Firmar con ElGamal *°*°*°")
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
