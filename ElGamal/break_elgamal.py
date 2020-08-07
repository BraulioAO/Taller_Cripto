#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 7. ELGAMAL
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

from math import log

def es_primo(p):
    """ Comprueba si un número p es primo o no mediante la operación
        módulo. Si "p mod n" es cero, significa que p es divisible 
        entre n, por lo que ya no es primo, sino sigue comprobando.
    """
    for n in range(2,p):
        if not p%n: #Si el residuo es cero, no es primo.
            return False
        else:
            pass
        return True


print("\n\t\t*°*°*° ElGamal *°*°*°")

nombre = input("\n\n\tIngrese el nombre de la víctima: ")

try: #Verifica que se ingrese un número, sino error.
    p = int(input("\n\tIngrese el valor p de {}: ".format(nombre)))
    if not es_primo(p):
        print("\n\t\t***El valor P no es primo***\n")
        exit()

    a = int(input("\n\tIngrese el valor α de {}: ".format(nombre)))
    if a >= p:
        print("\n\t\t***El valor Y debe ser menor que P ({})***\n".format(p))
        exit()

    kpub = int(input("\n\tIngrese la clave pública de {}: ".format(nombre)))
    if kpub >= p:
        print("\n\t\t***El valor de la clave pública debe ser menor que P ({})***\n".format(p))
        exit()

    val_init = input("\n\tIngrese el número desde donde desea comenzar la búsqueda de la clave privada: ")
    if val_init == '':
        val_init = 1
    else:
        val_init = int(val_init)
except ValueError:
    print("\n\t***El valor ingresado no es numérico***\n")
    exit()


try:
    print("\n\tBuscando clave privada comenzando en {}, espere un momento ...\n".format(val_init))

    # Calcula mediante fuerza bruta todas las posibles claves privadas (kpriv) con las que se 
    # puede obtener la misma clave pública (kpub). Para esto, dado que kpriv se encuentra
    # comprendida entre 1 < kpriv < p, es necesario buscar todos aquellos valores de kpriv
    # que sean igual a: kpub = (y^kpriv mod p), donde 'kpub, p, y' son los valores conocidos.
    
    #Crea lista de valores kpriv que cumplen con kpub = (y^kpriv mod p)
    for i in range(val_init,p):
        #print(i)
        if a**i%p == kpub:
            print("\t\tClave privada de {}: {}".format(nombre,i))
            exit()
    print("")
    exit()

except KeyboardInterrupt:
    print("\n\t*** Último valor probado: {} ***\n".format(i))
