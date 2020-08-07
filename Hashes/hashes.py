#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 2. HASHES
# N0MBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

import optparse
import hashlib 
import sys

# Función donde se declaran las banderas.
def options():
    parser = optparse.OptionParser()
    parser.add_option('-a','--md5-archivo',dest='md5_archivo',help='Hace uso de la función MD5 para obtener el hash de un archivo')
    parser.add_option('-b','--sha1-archivo',dest='sha1_archivo',help='Hace uso de la función SHA1 para obtener el hash de un archivo')
    parser.add_option('-c','--sha256-archivo',dest='sha256_archivo',help='Hace uso de la función SHA256 para obtener el hash de un archivo')
    parser.add_option('-d','--sha512-archivo',dest='sha512_archivo',help='Hace uso de la función SHA512 para obtener el hash de un archivo')
    parser.add_option('-e','--rmd160-archivo',dest='rmd160_archivo',help='Hace uso de la función RIPEM160 para obtener el hash de un archivo')
    parser.add_option('-A','--md5-texto',dest='md5_texto',help='Hace uso de la función MD5 para obtener el hash de una palabra o frase')
    parser.add_option('-B','--sha1-texto',dest='sha1_texto',help='Hace uso de la función SHA1 para obtener el hash de una palabra o frase')
    parser.add_option('-C','--sha256-texto',dest='sha256_texto',help='Hace uso de la función SHA256 para obtener el hash de una palabra o frase')
    parser.add_option('-D','--sha512-texto',dest='sha512_texto',help='Hace uso de la función SHA512 para obtener el hash de una palabra o frase')
    parser.add_option('-E','--rmd160-texto',dest='rmd160_texto',help='Hace uso de la función RIPEMD160 para obtener el hash de una palabra o frase')  
    opts,args = parser.parse_args()
    return opts

# Función que permite leer el archivo, si el archivo no se encuentra manda mensaje notificando y termina el programa.
def leer_archivo(nombre):
    try:
        f = open(nombre,'rb')
        datos = f.read()
        f.close
        return datos
    except:
        print ("\n\t\t*** No se encontró el archivo indicado :( *** \n")
        exit()

# Función para obtener el hash de un archivo, recibe la función hash a utilizar. Hace uso de la función leer_archivo
# en donde el archivo es el segundo argumento pasado en la linea de comandos. Regresa el hash.
def obtener_hash_archivo(funcion):
    h = hashlib.new(funcion)
    archivo = sys.argv[2]  
    contenido = leer_archivo(archivo)
    h.update(contenido)
    return h.hexdigest()

# Función para obtener el hash de una palabra o frase, recibe la función hash a utilizar.
# La palabra o frase es el segundo argumento pasado en la linea de comandos. Regresa el hash.
def obtener_hash_texto(funcion):
    h = hashlib.new(funcion)
    contenido = sys.argv[2]  
    h.update(contenido.encode('utf-8'))
    return h.hexdigest()


def main():
    if options().md5_archivo:
        titulo = "Hash en MD5 del archivo: "+options().md5_archivo
        tipo_hash = "MD5"
        hash_hex = obtener_hash_archivo("md5")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(128)
    elif options().sha1_archivo:
        titulo = "Hash en SHA1 del archivo: "+options().sha1_archivo
        tipo_hash = "SHA1"
        hash_hex = obtener_hash_archivo("sha1")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(160)
    elif options().sha256_archivo:
        titulo = "Hash en SHA256 del archivo: "+options().sha256_archivo
        tipo_hash = "SHA256"
        hash_hex = obtener_hash_archivo("sha256")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(256)
    elif options().sha512_archivo:
        titulo = "Hash en SHA512 del archivo: "+options().sha512_archivo
        tipo_hash = "SHA512"
        hash_hex = obtener_hash_archivo("sha512")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(512)
    elif options().rmd160_archivo:
        titulo = "Hash en RIPEMD160 del archivo: "+options().rmd160_archivo
        tipo_hash = "RIPEMD160"
        hash_hex = obtener_hash_archivo("rmd160")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(160)
    
    elif options().md5_texto:
        titulo = "Hash en MD5 de la palabra/frase: "+options().md5_texto
        tipo_hash = "MD5"
        hash_hex = obtener_hash_texto("md5")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(128)
    elif options().sha1_texto:
        titulo = "Hash en SHA1 de la palabra/frase: "+options().sha1_texto
        tipo_hash = "SHA1"
        hash_hex = obtener_hash_texto("sha1")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(160)
    elif options().sha256_texto:
        titulo = "Hash en SHA256 de la palabra/frase: "+options().sha256_texto
        tipo_hash = "SHA256"
        hash_hex = obtener_hash_texto("sha256")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(256)
    elif options().sha512_texto:
        titulo = "Hash en SHA512 de la palabra/frase: "+options().sha512_texto
        tipo_hash = "SHA512"
        hash_hex = obtener_hash_texto("sha512")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(512)
    elif options().rmd160_texto:
        titulo = "Hash en RIPEMD160 de la palabra/frase: "+options().rmd160_texto
        tipo_hash = "RIPEMD160"
        hash_hex = obtener_hash_texto("rmd160")
        hash_bin = bin(int(hash_hex,16))[2:].zfill(160)

    print ("\n\t\t"+titulo)
    print ("\nHash({}): {}".format(tipo_hash,hash_hex))
    print ("Binario({}): {}".format(tipo_hash,hash_bin))
    print ("\n*Longitud en caracteres: "+str(len(hash_hex)))
    print ("*Longitud en bits: "+str(len(hash_bin)))

# Se llama a la función main.
main()


