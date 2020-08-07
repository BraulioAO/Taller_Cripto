#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 5. DH (DEFFIE - HELLMAN)
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique


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

print("\n   Script que calcula la clave pública y simétrica del algoritmo DH a partir\
\n   del número P primo y Y, al igual que las claves privadas A y B dados.")

try:
    p = int(input("\n\n\tIngrese un número primo P: "))
    if not es_primo(p):
        print("\n\t\t***El valor P no es primo***\n")
        exit()

    y = int(input("\tIngrese número Y menor que P: "))
    if y >= p:
        print("\n\t\t***El valor Y debe ser menor que P ({})***\n".format(p))
        exit()

    kpriv_a = int(input("\tIngrese clave privada A: "))
    if kpriv_a >= p:
        print("\n\t\t***La clave privada de A debe ser menor que P ({})***\n".format(p))
        exit()

    kpriv_b = int(input("\tIngrese clave privada B: "))
    if kpriv_b >= p:
        print("\n\t\t***La clave privada de B debe ser menor que P ({})***\n".format(p))
        exit()
except ValueError:
    print("\n\t***El valor no es numérico***")
    exit()

kpub_a = y ** kpriv_a % p # Calcula clave pública de A
kpub_b = y ** kpriv_b % p # Calcula clave pública de B

ksim_a = kpub_b ** kpriv_a % p #Calcula clave simétrica para A
ksim_b = kpub_a ** kpriv_b % p #Calcula clave simétrica para B


#Impresión de los datos
print("\n\t{0:^10} {1:^15} {2:^15}".format("", "Claves para A", "Claves para B"))
print("\t{0:>10} {1:^15} {2:^15}".format("Privada", kpriv_a, kpriv_b))
print("\t{0:>10} {1:^15} {2:^15}".format("Pública", kpub_a, kpub_b))
print("\t{0:>10} {1:^15} {2:^15}\n".format("Simétrica", ksim_a, ksim_b))


