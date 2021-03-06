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

#Se define alfabeto para obtener equivalente numérico de funciones Hash.
dic = {'A':1,'B':2,'C':3,'D':4,'E':5,'F':6,'G':7,'H':8,
       'I':9,'J':10,'K':11,'L':12,'M':13,'N':14,'Ñ':15,'O':16,
       'P':17,'Q':18,'R':19,'S':20,'T':21,'U':22,'V':23,'W':24,
       'X':25,'Y':26,'Z':27,'0':28,'1':29,'2':30,'3':31,'4':32,
       '5':33,'6':34,'7':35,'8':36,'9':37}


def mcd(a, b):
    """ Calcula el máximo común divisor de dos números mediante el
        algoritmo de Euclides

        Args:
            a(int): Primer número
            b(int): Segundo número

        Returns:
            int: Máximo común divisor
    """
    if b == 0: #Caso base, el residuo es cero
        return a

    #Mientras el residuo no sea cero, se llama recursivamente
    return mcd(b, a%b)

def egcdinv(a,b):
    """ Se utiliza el algoritmo extendido de euclides para calcular el 
        inverso módulo m de e*d --- 1 mod phi (--- es congruente)
        
        Args:
            a(int): Primer número (valor e)
            b(int): Segundo número (valor phi)

        Returns:
            int: Inverso del valor 'e'
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

        Args:
            p(int): número a comprobar si es primo mayor a 101
    """
    if p <= 101:
        print("\n\t\t***El valor ingresado debe ser un número primo mayor a 101***\n")
        exit()

    for n in range(2,p):
        if not p%n: #Si el residuo es cero, no es primo.
            print("\n\t\t***El valor {} no es primo***\n".format(p))
            exit()

def menor(n1,n2):
    """ Comprueba que 'n1' sea menor que 'n2', sino termina programa.
        
        Args:
            n1(int): Primer número
            n2(int): Segundo número
    """
    if n1 >= n2:
        print("\n\t\t***El número ingresado debe ser menor a {}***\n".format(n2))
        exit()

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
    """ Función para la creación de la firma digital con El Gamal.

        Args:
            hash_datos(bytes): hash de los datos del archivo a firmar
            nombre_archivo(str): Nombre del archivo a firmar
            clave_compartir(str): Cadena "Clave de nnn bits: <<clave>>", con la clave de cifrado, en caso de estar cifrado.
    """
    try:
        p = int(input("\n\tIngrese el valor de p: ")) #Número primo
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.

        a = int(input("\n\tIngrese el valor de α: ")) #Número aleatorio menor que P
        menor(a,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        b = int(input("\n\tIngrese el valor de β: ")) #Clave pública
        menor(b,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

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

        #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
        M = 0 # h(M)
        for i in hash_datos.hex().upper():
            M += dic[i]

        h_inv = egcdinv(h, phi_p) #Obtiene el inverso de: H-1 = inv(H,ϕp)
        r = (a**h) %p #Valor r = (α ^ H) mod p
        s = ((M - l*r) * h_inv) % phi_p #Valor s = ((h(M) - (λ*r))* H-1) mod ϕp

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
    """ Función para verificar la firma digital creada con El Gamal.

        Args:
            hash_datos_recividos(bytes): hash de los datos del archivo a verificar.
    
        Returns:
            bool: Regresa True si la firma es correcta, sino False.
    """
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

    N1 = (r**s) % p #Valor N1 = (r^s) mod p
    N2 = (b**r) % p #Valor N2 = (b^r) mod p
    k1 = (N1*N2) % p #Valor k1 = (N1*N2) mod p
    
    #Se obtiene equivalente numérico del hash haciendo uso del diccionario 'dic'
    M = 0 #h(M)
    for i in hash_datos_recividos.hex().upper():
        M += dic[i]

    k2 = (a**M) % p #Valor k2 = (α^h(M)) mod p

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
        

        else: #Se ingresó opción inválida, volver a intentar
            print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")
        

main()
