#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 4. AES (ADVANCED ENCRYPTION STANDARD)
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

from base64 import b64encode, b64decode
from datetime import datetime
from hashlib import sha256
from Crypto import Random
from Crypto.Cipher import AES

import optparse

key_bytes = 32
pad = lambda s: s+(key_bytes-len(s)%key_bytes)*chr(key_bytes-len(s)%key_bytes).encode('utf-8')
unpad = lambda s: s[:-ord(s[len(s)-1:])]

def options():
    """ Función donde se definen las banderas a utilizar en terminal con ayuda de la librería 'optparse'.
    """
    parser = optparse.OptionParser()
    parser.add_option("-a", "--cifrar-texto", action="store", type="string", dest="cifrar_texto", 
                        help="Ingrese el mensaje a cifrar en modo texto")
    parser.add_option("-b", "--cifrar-archivo", dest="cifrar_archivo", 
                        help="Ingrese el archivo a cifrar")
    parser.add_option("-X", "--clave-128", dest="clave_128", 
                        help="Cifrado con clave de 128 bits")
    parser.add_option("-Y", "--clave-192", dest="clave_192", 
                        help="Cifrado con clave de 192 bits")
    parser.add_option("-Z", "--clave-256", dest="clave_256", 
                        help="Cifrado con clave de 256 bits")
    parser.add_option("-V", "--vector", dest="vector", 
                        help="Ingresar vector de inicialización, si no se ingresa, se coloca uno aleatorio")
    parser.add_option("-C", "--cifrar", action="store_true", default=False, dest="cifrar", 
                        help="Usar modo cifrado")
    parser.add_option("-D", "--descifrar", dest="descifrar", 
                        help="Usar modo de descifrado")

    opts,args = parser.parse_args()
    return opts

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
        print ("\n\t\t*** No se encontró el archivo "+nombre+" :( *** \n")
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


def cifrar(datos, password, iv):
    datos = pad(datos)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return b64encode(iv+cipher.encrypt(datos))

def descifrar(datos_enc, password, iv):
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(datos_enc))


def main():
    """
    Programa principal en el que se lleva acabo:
        - El manejo de errores con el uso de las banderas.
        - La lectura del mensaje y la clave a utilizar para cifrar/descifrar.
        - La verificación de que la clave sea de 8 caracteres ascii o 16 caracteres hexadecimales.
        - El cifrado y descifrado del mensaje, obtención de hash y guardado en archivos segun sea el caso.
    """

    #Manejo de errores por banderas excluyentes o falta de banderas
    if options().cifrar and options().descifrar:
        print("\n\tOpciones -C y -D mutuamente excluyentes.\n")
        exit()
    elif not options().cifrar and not options().descifrar:
        print("\n\tSin opción de difrado/descifrado.")
        print("\t   -Para cifrar use la bandera -C junto con -a o -b")
        print("\t   -Para descifrar un archivo use la bandera -D\n")
        exit()
    elif options().cifrar and not (options().cifrar_texto or options().cifrar_archivo):
        print("\n\tSin texto o archivo a cifrar. Intente usar las banderas -a o -b\n")
        exit()
    elif options().descifrar and (options().cifrar_texto or options().cifrar_archivo):
        print("\n\tBanderas -a o -b no admitidas junto con la bandera -D")
    elif options().cifrar_texto and options().cifrar_archivo:
        print("\n\tOpciones -a y -b mutuamente excluyentes.\n")
        exit()
    elif not (options().clave_128 or options().clave_192 or options().clave_256):
        print("\n\tSin clave para cifrar/descifrar. Intente usar las banderas -X, -Y o -Z\n")
        exit() 
    elif options().clave_128 and (options().clave_192 or options().clave_256):
        print("\n\tOpciones -X, -Y y -Z mutuamente excluyentes.\n")
        exit()
    elif options().clave_192 and (options().clave_128 or options().clave_256):
        print("\n\tOpciones -X, -Y y -Z mutuamente excluyentes.\n")
        exit()
    elif options().clave_256 and (options().clave_128 or options().clave_192):
        print("\n\tOpciones -X, -Y y -Z mutuamente excluyentes.\n")
        exit()


    clave = bytes()
    try:
        if options().clave_128:
            clave = options().clave_128.encode('ascii')
            key = sha256(clave).digest()[:16]
            key_bytes = 16
        elif options().clave_192:
            clave = options().clave_192.encode('ascii')
            key = sha256(clave).digest()[:24]
            key_bytes = 24
        elif options().clave_256:
            clave = options().clave_256.encode('ascii')
            key = sha256(clave).digest()
            key_bytes = 32
    except:
        print("\n\tSolo se permiten contraseñas con caracteres ASCII\n")
        exit()

    
    #Lectura de la mensaje y clave para cifrar/descifrar
    if options().cifrar_texto: #Mensaje en texto
        mensaje = options().cifrar_texto.encode('utf-8') 
    elif options().cifrar_archivo: #Mensaje en archivo
        mensaje = leer_archivo(options().cifrar_archivo)


    #CIFRADO: Se selecciona la bandera -C
    if options().cifrar:
        if options().vector: #Bander -V para ingresar vector de inicialización (iv)
            try:
                iv_init = options().vector.encode('ascii') #Recupera vector y codifica a ascii
                iv_init = sha256(iv_init).digest()[:16] #Calcula hash y se toman como iv los primeros 16 bytes.
            except:
                print("\n\tEl vector debe contener solo caracteres ASCII\n")
                exit()
        else: #No bandera -V, vector de inicialización aleatorio
            iv_init = Random.new().read(AES.block_size)


        print("\n   Comenzando el cifrado...")
        if options().cifrar_archivo: #Cifrado de archivo
            print("   Cifrando el archivo: "+options().cifrar_archivo)
            name_file_save = options().cifrar_archivo
            extencion = name_file_save.split('.')
            if len(extencion) >= 2:
                extension = extencion[-1]
            else:
                extension = ''
            name_file_save += "_cifrado_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+'.'+extension) #Nombre del archivo cifrado
        else: #Cifrado de texto
            print("   Cifrando la frase: "+options().cifrar_texto)
            name_file_save = "frase.txt_cifrado_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+'.txt') #Nombre del archivo cifrado

        datos_cifrados = cifrar(mensaje, key, iv_init) #Funión para cifrar la información
        guardar_archivo(name_file_save, datos_cifrados)
        #print(datos_cifrados)

        if options().clave_128:
            print("\n   Cifrado de 128 bits realizado, guardado en: "+name_file_save+"\n")
        elif options().clave_192:
            print("\n   Cifrado de 192 bits realizado, guardado en: "+name_file_save+"\n")
        elif options().clave_256:
            print("\n   Cifrado de 256 bits realizado, guardado en: "+name_file_save+"\n")


    if options().descifrar:
        datos_cif = b64decode(leer_archivo(options().descifrar)) #Leemos datos cfrados

        if options().vector: #Bander -V para ingresar vector de inicialización (iv)
            try:
                iv_init = options().vector.encode('ascii') #Recupera vector y codifica a ascii
                iv_init = sha256(iv_init).digest()[:16] #Calcula hash y se toman como iv los primeros 16 bytes.
            except:
                print("\n\tEl vector debe contener solo caracteres ASCII\n")
                exit()
        else: #No bandera -V, recupera vector del inicio del mensaje cifrado
            iv_init = datos_cif[:16]

        datos_cif = datos_cif[16:] #Recupera mensaje cifrado despues del vector inicial


        print("\n   Comenzando el descifrado...")
        print("   Descifrando el archivo: "+options().descifrar)
        name_file_save = options().descifrar
        extencion = name_file_save.split('.')
        if len(extencion) >= 2:
            extension = extencion[-1]
        else:
            extension = ''
        name_file_save += "_descifrado_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+'.'+extension) #Nombre del archivo cifrado

        datos_descifrados = descifrar(datos_cif, key, iv_init) #Funión para cifrar la información
        if len(datos_descifrados) == 0:
            print("\n   No se pudo desencriptar el archivo: "+name_file_save)
            print("   Verefique que la clave sea correcta\n")
            exit()

        guardar_archivo(name_file_save, datos_descifrados)
        #print(datos_descifrados)
        #print(len(datos_descifrados))

        if options().clave_128:
            print("\n   Descifrado de 128 bits realizado, guardado en: "+name_file_save+"\n")
        elif options().clave_192:
            print("\n   Descifrado de 192 bits realizado, guardado en: "+name_file_save+"\n")
        elif options().clave_256:
            print("\n   Descifrado de 256 bits realizado, guardado en: "+name_file_save+"\n")

main()
