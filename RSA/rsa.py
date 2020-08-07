#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 6. RSA
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

from random import randrange
from functools import reduce


#Se define alfabeto a utilzar en el cifrado
alfabeto = {'A':1, 'B':2, 'C':3, 'D':4, 'E':5, 'F':6, 'G':7, 'H':8, 'I':9, 'J':10, 'K':11, 
            'L':12, 'M':13, 'N':14, 'Ñ':15, 'O':16, 'P':17, 'Q':18, 'R':19, 'S':20, 'T':21,
            'U':22, 'V':23, 'W':24, 'X':25, 'Y':26, 'Z':27, '0':28, '1':29, '2':30, '3':31,
            '4':32, '5':33, '6':34, '7':35, '8':36, '9':37}

#Se define el inverso del alfabeto
alfabeto_inv = {1:'A', 2:'B', 3:'C', 4:'D', 5:'E', 6:'F', 7:'G', 8:'H', 9:'I', 10:'J', 11:'K', 
                12:'L', 13:'M', 14:'N', 15:'Ñ', 16:'O', 17:'P', 18:'Q', 19:'R', 20:'S', 21:'T',
                22:'U', 23:'V', 24:'W', 25:'X', 26:'Y', 27:'Z', 28:'0', 29:'1', 30:'2', 31:'3',
                32:'4', 33:'5', 34:'6', 35:'7', 36:'8', 37:'9'}


def es_primo_mayor_101(p):
    """ Comprueba que p sea un numero primo mayor que 101, mediante la 
        operación módulo. Si "p mod n" es cero, significa que p es divisible 
        entre n (101 < n < p), por lo que ya no es primo, sino se sigue comprobando.
    """
    if p <= 101:
        print("\n\t\t***El valor ingresado debe ser mayor a 101***\n")
        exit()

    for n in range(2,p):
        if not p%n: #Si el residuo es cero, no es primo.
            print("\n\t\t***El valor {} no es primo***\n".format(p))
            exit()
        else:
            pass #Sigue comprobando

def mcd(a, b):
    """ Calcula el máximo común divisor de dos números mediante el
        algoritmo de Euclides
    """
    if b == 0: #Caso base, el residuo es cero
        return a

    #Mientras el residuo no sea cero, se llama recursivamente
    return mcd(b, a%b)

def mcd_e(a, b):
    """ Calcula el máximo común divisor de dos números mediante el
        algoritmo de euclides extendido, en el cual mcd(a,b) = as + bt,
        donde s y t son números enteros.
    """
    if b == 0: #Caso base, cuando el residuo es cero
        return(a, 1, 0) #a <- mcd

    #Mientras el residuo no sea cero, se llama recursivamente
    d,s,t = mcd_e(b, a%b) #d <- mcd
    return d, t, s-(a//b)*t

def mod_inv(a,m):
    """ Se utiliza el algoritmo extendido de euclides para calcular el 
        inverso módulo m de e*d --- 1 mod phi
    """
    mcd,t,s = mcd_e(a,m)
    if mcd!=1:
        print("\n\t\t***No se pudo calcular el inverso de 'e'***\n")
        exit()
    return t%m #Regresa el inverso 'd'

def equivalente_alfabeto(num):
    equivalente = []
    n = num
    while True:
        q = n//37 #Calculamos division entera
        equivalente.append(n%37) #Calculamos residuo y agrega a la lista
        if q < 37: #Si la división es menor a 37, agregamos ultima división a la lista
            equivalente.append(q)
            break
        n = q
    #print(equivalente)
    equivalente.reverse()
    #print(equivalente)
    return equivalente #Regresamos lista al revés.

def cifrado_cesar(li,n, dir):
    li_cesar = []
    if dir == 'cifrar':
        for pos,elem in enumerate(li):
            li_cesar.append((elem+n-1)%37+1)
    elif dir == 'descifrar':
        for pos,elem in enumerate(li):
            li_cesar.append((elem-n-1)%37+1)
    
    return li_cesar










def obtencion_claves():
    try:
        p = int(input("\n\t\tIngrese su número p: "))
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.
        
        q = int(input("\n\t\tIngrese su número q: "))
        es_primo_mayor_101(q) #Comprueba que sea primo mayor a 101, sino termina programa.

        n=p*q
        phi =(p-1)*(q-1)
        print("\n\t\tValor de n: {}".format(n))
        print("\n\t\tValor de \u0278(n): {}".format(phi))

        e=randrange(2,phi) #Genera numero e en el rango: 1 < e < phi
        while True:
            print("\n\t\t¿Desea ingresar el valor de 'e', o prefiere que el programa lo busque?")
            op = input("\t\tPara ingresar el número presione Y, para que el programa lo indique presione N: ").lower()
            
            if op == 'y': #Se ingresa el número 'e'
                e = int(input("\n\t\tIngrese su número e: "))

                while mcd(e,phi) != 1: #Se verifica que el mcd(e,phi) sea uno.
                    print("\n\t\t***mcd(e,\u0278) no es igual a 1, intente con otro valor de 'e'***")
                    e = int(input("\n\t\tIngrese su número e: "))
                break

            elif op == 'n': #Se genera el número 'e'
                while mcd(e,phi) != 1:
                    e = randrange(2,phi) #Genera numero e en el rango: 1 < e < phi

                print("\n\t\tEl valor de 'e' es: {}".format(e))
                break
            
            print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")

        d = mod_inv(e,phi) #Calcula el inverso de 'e'
        print("\n\t\tSu clave pública es: ({}, {})".format(n, e))
        print("\n\t\tSu clave privada es: ({})\n".format(d))
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()


def cifrado():
    palabra = input("\n\t\tIngrese la palabra a cifrar: ").upper()

    try:
        n = int(input("\n\t\tIngrese el valor de n: "))
        e = int(input("\n\t\tIngrese el valor de e: "))
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    #Codificamos la palabra a valor numérico: palabra_codif=val*(37^e), donde e es la posición de la letra,
    #y val es el valor numérico de cada letra deacuerdo al alfabeto definido.
    palabra_codif = 0
    try:
        for exp,letra in enumerate(palabra):
            palabra_codif += alfabeto[letra]*(37**exp)
    except:
        print("\n\t\t***Palabra a cifrar con caracteres inválidos***\n")
        exit()

    #Verificamos que el valor del mensaje codificado sea menor el valor n ingresado por el usuario.
    if palabra_codif < n:
        print("\n\t\tCifrando ...")
        valor_cifrado = (palabra_codif**e)%n #Ciframos el mensaje
        msj_equivalente = equivalente_alfabeto(valor_cifrado) #Transformamos a numeros para obtener equivalente alfabético
        #Aplicamos cifrado cesar len(palabra) posiciones a la derecha antes de obtener el equivalente alfabético
        msj_cesar = cifrado_cesar(msj_equivalente, len(palabra), 'cifrar') 

        #Transformamos los valores del mensaje con el cifrado cesar a letras utilizando el alfabeto inverso.
        msj_cifrado = []
        for val in msj_cesar:
            msj_cifrado.append(alfabeto_inv[val])
        try:
            msj_cifrado.append(alfabeto_inv[len(palabra)]) #Agrega como último caracter longitud del mensaje original codificado con el alfabeto.
        except:
            print("\n\t\tEl mensaje a cifrar no puede ser mayor a 37 caracteres\n")
            exit()

        cadena_cifrada = "".join(msj_cifrado) #Transforma la lista en una cadena
            
        #print("\n\nmensaje codificado: {}".format(palabra_codif))
        #print("valor cifrado: {}".format(valor_cifrado))
        #print("Equivalente para decodificado: {}".format(msj_equivalente))
        #print("Cifrado cesar a equivalente con n = {}: {}".format(len(palabra),msj_cesar))
        #print("Cadena del mensaje cifrado: {}".format(cadena_cifrada))

        print("\n\t\tLa palabra cifrada es: {}\n".format(cadena_cifrada))
    
    else:
        print("\n\t\t***El valor del mensaje codificado a cifrar ({}) es mayor***".format(palabra_codif))
        print("\t\t***que el valor de n ({}), intente cifrar un mensaje más corto\n***".format(n))
        exit()

def descifrado():
    palabra = list(input("\n\t\tIngrese la palabra a descifrar: ").upper())

    try:
        n = int(input("\n\t\tIngrese el valor de n: "))
        d = int(input("\n\t\tIngrese el valor de d: "))
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

    #Decodifica el mensaje cifrado con cesar a valores numéricos utilizando el alfabeto.
    deco_msj_cifrado_cesar = []
    try:
        for val in palabra[:-1]:
            deco_msj_cifrado_cesar.append(alfabeto[val])
    except:
        print("\n\t\t***Palabra a descifrar con caracteres inválidos***\n")
        exit()
    
    long_msj = alfabeto[palabra[-1]] #Obtenemos la longitud del mensaje original

    #Aplicamos descifrado cesar len(palabra) posiciones a la izquierda
    msj_descifrado_cesar = cifrado_cesar(deco_msj_cifrado_cesar, long_msj, 'descifrar') 

    #Decodificado de los valores numéricos a un único valor, por ejemplo, si tenemos los valores <<5,14,24>>,
    #entonces se realizan las siguientes operaciones:
    #   cifrado = (5*37)+14 = 199
    #   cifrado = (199*37)+24 = 7387
    palabra_cifrada = reduce(lambda a,b : a*37+b, msj_descifrado_cesar) #Reduce los valores a un único valor mediante la función reduce.
    
    if palabra_cifrada < n:
        print("\n\t\tDescifrando ...")
        valor_descifrado=(palabra_cifrada**d)%n #Obtenemos valor del mensaje descifrado

        msj_equivalente_descifrado = equivalente_alfabeto(valor_descifrado) #Transformamos a numeros para obtener equivalente alfabético

        palabra_descifrada = [] #Decodificamos los valores numéricos a letras mediante el alfabeto inverso.
        for val in msj_equivalente_descifrado:
            palabra_descifrada.append(alfabeto_inv[val])

        palabra_descifrada.reverse()

        cadena_descifrada = "".join(palabra_descifrada) #Transforma la lista en una cadena

        #print("\n\nPalabra decodificado: {}".format(deco_msj_cifrado_cesar))
        #print("Palabra decodificada descifrada mediante cifrado Cesar: {}".format(msj_descifrado_cesar))
        #print("Valor palabra cifrada: {}".format(palabra_cifrada))
        #print("Valor palabra descifrada: {}".format(valor_descifrado))
        #print("Equivalente palabra descifrada para decodificar {}".format(msj_equivalente_descifrado))
        #print("Mensaje descifrado: {}".format(palabra_descifrada))

        print("\n\t\tEl descifrado es: {}\n".format(cadena_descifrada))
    else:
        print("\n\t\t***El valor de la palabra cifrado ({}) es mayor***".format(palabra_codif))
        print("\t\t***que el valor de n ({}), verifique la palabra a descifrar***".format(n))
        exit()


def main():
    print("\n\t\t *°*°*° RSA *°*°*°")
    print("\n\n\tSeleccione una opción:")
    print("\n\ta. Obtención de claves.")
    print("\tb. Cifrado")
    print("\tc. Descifrado")

    while True:
        op = input("\tIngrese su opción: ").lower()
        if op == 'a':
            obtencion_claves()
            exit()
        elif op == 'b':
            cifrado()
            exit()
        elif op == 'c':
            descifrado()
            exit()

        print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")


main()