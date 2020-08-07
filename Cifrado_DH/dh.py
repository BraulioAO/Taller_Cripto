#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 5. DH (DEFFIE - HELLMAN)
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


print("\n\t\t*°*°*° Diffie y Hellman *°*°*°")

nombre = input("\n\n\tIngrese el nombre de la víctima: ")

try: #Verifica que se ingrese un número, sino error.
    p = int(input("\n\tIngrese el valor P acordado: "))
    if not es_primo(p):
        print("\n\t\t***El valor P no es primo***\n")
        exit()

    y = int(input("\n\tIngrese el valor Y acordado: "))
    if y >= p:
        print("\n\t\t***El valor Y debe ser menor que P ({})***\n".format(p))
        exit()

    kpub = int(input("\n\tIngrese la clave pública de {}: ".format(nombre)))
    if kpub >= p:
        print("\n\t\t***El valor de la clave pública debe ser menor que P ({})***\n".format(p))
        exit()

except ValueError:
    print("\n\t***El valor ingresado no es numérico***\n")
    exit()

kpriv = int(log(kpub,y)%p) #Calcula posible clave privada mediante: kpriv = logY(kpub) mod p
print("\n\tPosible clave secreta de {}: {:d}".format(nombre, kpriv))

while True:
    op = input("\n\t¿Desea ver la lista completa de los números posibles? Y/N: ").lower()
    if op == 'y':
        # Calcula mediante fuerza bruta todas las posibles claves privadas (kpriv) con las que se 
        # puede obtener la misma clave pública (kpub). Para esto, dado que kpriv se encuentra
        # comprendida entre 1 < kpriv < p, es necesario buscar todos aquellos valores de kpriv
        # que sean igual a: kpub = (y^kpriv mod p), donde 'kpub, p, y' son los valores conocidos.
        
        #Crea lista de valores kpriv que cumplen con kpub = (y^kpriv mod p)
        kpriv_posibles = list(filter(lambda i: y**i%p == kpub, range(2,p)))
        print("\n\t{}\n".format(kpriv_posibles))
        exit()
    elif op == 'n':
        print("")
        exit()

    print("\n\t\t*** Opción inválida, vuelva a intentar ***")

