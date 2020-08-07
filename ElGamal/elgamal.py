#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# TALLER VIRTUAL DE CRIPTOGRAFÍA PRÁCTICA
# 7. ELGAMAL
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

import random
import os

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

def egcdinv(a,b):
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

def primo(num):
    """ Comprueba que 'num' sea un numero primo mayor que 1, mediante la 
        operación módulo. Si "num mod n" es cero, significa que 'num' es divisible 
        entre n (2 < n < num), por lo que ya no es primo, sino se sigue comprobando.
    """
    if num < 1: #Verifica que sea un número positivo mayor a 1
        return False
    for i in range(2, num):
        if num % i == 0: #Si el residuo es cero, no es primo
            return False
    return True

def menor(n1,n2):
    """ Comprueba que 'n1' es menor que 'n2', sino termina programa. """
    if n1 >= n2:
        print("\n\t\t***El número ingresado debe ser menor a {}***\n".format(n2))
        exit()

def obtener_clave():
    os.system("clear")
    print("\n\t\t *°*°*° Creación de clave *°*°*°\n")
    
    # Se ingresan valores p, α y se genera o ingrsea valor λ (clave privada). En donde:
    #   - P, es un número primo grande
    #   - α, es un número aleatorio menor a p
    #   - λ, clave privada, debe ser número primo menor a p
    # Se calcula clave pública (β) mediante: clave_pública = (α^clave_privada) mod p
    try:
        p = int(input("\nIngrese su número p: "))
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.
        
        a = int(input("\nIngrese el valor de α: "))
        menor(a,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        print ("\n¿Desea ingresar el valor de su clave privada, o prefiere que sea asignada?")
        print("\nSeleccione una opción:")
        print("   x. Ingresar clave")
        print("   y. Asignar clave")    

        while True:
            priv = input("   Ingrese su opción: ").lower()
            
            if priv == 'x': #Se ingresa la clave privada
                l = int(input ("\t\nIngrese el valor de su clave privada: "))
                menor(l,p) #Comprueba que la clave sea menor que p, sino termina programa.
                es_primo_mayor_101(l) #Comprueba que sea primo mayor a 101, sino termina programa.
                break
            
            elif priv == 'y': #Genera la clave privada
                l = 0
                while not primo(l): #Se generan valores aleatorios hasta que sea un número primo.
                    l = random.randint(a,p) #Generamos clave privada aleatoria
                print("\n\tValor asignado (λ): ",l)
                break

            print("\n\t*** Opción inválida, vuela a intentar ***\n")

        b =(a**l) % p # Se calcula la clave pública como: β = (α^λ) mod p
        print("\n\tSu clave pública (β) es: {}\n".format(b))

    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

def cifrado():
    os.system("clear")
    print("\n\t\t *°*°*° Cifrado *°*°*°\n")
    
    # Codificamos la palabra a valor numérico 'N', en donde N es la suma de los 
    # valores val*(37^e), donde e es la posición de la letra, y val es el valor 
    # numérico de cada letra deacuerdo al alfabeto definido.
    try:
        N = 0

        palabra = input("\nIngrese la palabra a cifrar: ").upper()
        for exp,letra in enumerate(palabra):
            N += dic[letra]*(37**exp)
        print("\nValor de N: ",N)
    except:
        print("\n\t\t***Palabra a cifrar con caracteres inválidos***\n")
        exit()

    # Se ingresan valores p, α y β, y se genera o ingresa valor υ.
    # Se calculan N₁ y N₂, que representan el mensaje cifrado. En donde:
    #    - N₁ = (α^υ) mod p
    #    - N₂ = (N * β^υ) mod p
    try:
        p = int(input("\nIngrese el valor de p: "))
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.

        if p < N:
            print("\n\t***El valor P debe ser mayor al número N equivalente del mensaje***\n")
            exit()
        a = int(input("\nIngrese el valor de α: "))
        menor(a,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        b = int(input("\nIngrese el valor de β: "))
        menor(b,p) #Comprueba que 'a' sea menor que 'p', sino termina programa

        print ("\n¿Desea ingresar el valor de υ, o prefiere que sea asignada?") #υ es un número de sesión
        print("\nSeleccione una opción:")
        print("   h. Ingresar el valor")
        print("   i. Asignar valor")    

        u = 0
        while True:
            priv = input("   Ingrese su opción: ").lower()

            if priv == 'h': #Se ingresa el valor
                u = int(input ("\nIngrese el valor de υ: "))
                menor(u,p) #Comprueba que el valor sea menor que p, sino termina programa.
                break

            elif priv == 'i': #Genera valor
                u = random.randint(1,p) #Generamos valor aleatorio menor a p
                print("\n\tValor de υ asignado: ",u)
                break

            print("\n\t*** Opción inválida, vuela a intentar ***\n")

        primero = (a**u)%p # Se calcula N₁ = (α^υ) mod p
        segundo = (N * b**u) % p #Se calcula N₂ = (N * β^υ) mod p
        
        print("\n\tValores para realizar el descifrado (N₁,N₂) = ({},{})\n".format(primero, segundo))
        
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()

def descifrado():
    os.system("clear")
    print("\n\t\t *°*°*° Descifrado *°*°*°\n")
    
    # Se ingresan valores N₁, N₂, p y λ
    # Se calculan n3, n4 y n4 para descifrar el mensaje, en donde:
    #    - N3 = (N1^λ) mod p
    #    - N4 = inv(N3, p), Inverso multiplicativo usando algoritmo extendido de Euclides
    #    - N4 = (N2 * N4) mod p, mensaje descifrado pero codificado
    try:
        n1 = int(input("\nIngrese el valor N₁: "))
        n2 = int(input("\nIngrese el valor N₂: "))
        p = int(input("\nIngrese el valor de p: "))
        es_primo_mayor_101(p) #Comprueba que sea primo mayor a 101, sino termina programa.
        l = int(input("\nIngrese el valor de λ: ")) #Clave privada
        menor(l,p) #Comprueba que la clave sea menor que p, sino termina programa.
        es_primo_mayor_101(l) #Comprueba que sea primo mayor a 101, sino termina programa.

        n3 = (n1**l)%p
        n4 = egcdinv(n3,p) #Calcula el inverso multiplicativo entre n3 y p usando el algoritmo extendido de Euclides.
        nf = (n2*n4)%p
    except ValueError:
        print("\n\t\t***El valor ingresado no es numérico***\n")
        exit()


    # Se realiza reiteradamente la división del cociente actual entre 37 para 
    # obtener su residuo y un nuevo cociente sobre el cual volver a dividir.
    # Al final se obtiene el mensaje decodificado a formato numérico.
    cocientes = [nf] #Se agrega el mensaje codificado a la lista de cocientes
    residuos = [] #Lista que contiene el mensaje descifrado en formato numérico
    while cocientes[-1]>38:
        residuos.append(int(cocientes[-1]%37)) #Se calula el residuo del último cociente entre 37.
        cocientes.append(int(cocientes[-1]/37)) #Se calcula el nuevo cociente con el cociente pasado entre 37. 
    residuos.append(cocientes[-1])

    palabra_descifrada = [] #Decodificamos los valores numéricos a letras mediante el diccionario DicI
    for val in residuos:
        palabra_descifrada.append(dicI[val])
    
    cadena_descifrada = "".join(palabra_descifrada) #Transforma la lista a una cadena.
    print("\n\tEl mensaje descifrado es: {}\n". format(cadena_descifrada))



def main():
    print("\n\t\t *°*°*° ElGamal *°*°*°")
    print("\n\nSeleccione una opción: ")
    print("   a. Creación de clave pública.")
    print("   b. Cifrado")
    print("   c. Descifrado")

    while True:
        opcion = input("   Ingrese su opción: ").lower()
        
        if opcion == 'a':
            obtener_clave()
            exit()
        elif opcion == 'b':
            cifrado()
            exit()
        elif opcion == 'c':
            descifrado()
            exit()

        print("\n\t\t*** Opción inválida, vuelva a intentar ***\n")
        

main()
