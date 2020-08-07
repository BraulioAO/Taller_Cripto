#!/usr/bin/python3

# UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
# FACULTAD DE INGENIERÍA
# MANUAL DE ACTIVIDADES PRÁCTICAS DE CRIPTOGRAFÍA
# 3. DES (DATA ENCRYPTION STANDARD)
# NOMBRE DEL ALUMNO: Arrieta Ocampo Braulio Enrique

import optparse
import binascii
import base64
import hashlib
from datetime import datetime

#Lista con 56 índices entre 1 y 64.
PC_1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,21,13,5,28,20,12,4]

#Lista con 48 índices entre 1 y 56
PC_2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
        26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

LeftShifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] #Lista con 16 números de rotaciones.

#Lista con 64 índices del 1 al 64 mezclados
IP1 = [ 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

#Lista con 48 índices entre 1 al 32.
E = [32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1]

#Lista con 64 índices del 1 al 64 mezclados
IP_1 = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

#Lista con 32 índices del 1 al 32 mezclados.
P1 = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
      2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]


# Lista S[8][4][16] con valores del 0 al 15.
S = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
    ]





#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~Conversión de clave y generación de subclaves~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def clave_bin(clave):
    """ Convierte una cadena de texto como clave a una lista en binario utilizando codificación 'utf-8'.
        Args:
            clave(str): clave de cifrado o descifrado (8 caracteres ascii o 16 caracteres hexadecimales)

        Returns:
            list of bits: clave en binario (64 bits).
    """
    #print ("\n\t\t***Conversión de clave de texto a binario***")
    texto_bin = bin(int(clave,16))[2:].zfill(64) #Convierte la clave de hexadecimal a binario.
    return list(map(int,texto_bin)) #Regresa la clave binaria en forma de lista



def PC1(clave):
    """ Reordena la lista 'clave' de 64 elementos (bits) a otra de 56 elementos (bits) seleccionando
        solo aquellos cuyo índice está dado por la lista PC_1 (que contiene 56 índices), y divide
        en dos la clave reordenada.
         
        Args:
            clave(list of bits): clave en binario (64 bits).

        Returns:
            C(list of bits): mitad izquierda de la clave reordenada (28 bits).
            D(list of bits): mitad derecha de la clave reordenada (28 bits).
    """
    #print ("\n\t\t***Reordenar clave a 56 bits***")
    clave.insert(0,0) #Inserta un cero al inicio de la lista para ignorar el índice cero.
    CD = [clave[i] for i in PC_1] #Reordena clave de 64 a 56 bits con los elementos cuyos índices estan dados por la lista PC_1.
    C = CD[:28] #Se divide la clave reordenada en dos mitades.
    D = CD[28:]
    return C,D 



def subclaves(clave,n):
    """ Rota la lista 'clave' n veces a la izquierda para generar una
        nueva subclave a partir de esta.

        Args:
            clave(list of bits): clave en binario (64 bits).
            n(int): número de rotaciones a la izquierda.

        Returns:
            list of bits: clave rotada 'n' veces a la izquierda.
    """
    #print ("\n\t***Primera parte para generación de 16 subclaves***")
    return clave[n:] + clave[:n] #Equivalencia al código de abajo comentado
    #subclave = clave[n:]
    #for i in range(0,n):
    #    subclave.append(clave[i])
    #return subclave



def PC2(C,D):
    """ Suma las listas 'C' y 'D' de 28 elementos cada una, y reordena los elementos a 
        otra nueva lista de 48 elementos seleccionando solo aquellos cuyo índice está 
        dado por la lista PC_2 (que contiene 48 elementos).
         
        Args:
            C(list of bits): mitad izquierda de una clave en binario (28 bits).
            D(list of bits): mitad derecha de una clave en binario (28 bits).

        Returns:
            nclave(list of bits): clave en binario reordenada (48 bits).
    """
    #print ("\n\t***Segunda parte para generación de 16 subclaves***")
    clave = C+D #Suma las listas
    clave.insert(0,0) #Inserta un cero al inicio de la lista para ignorar al índice cero. 
    nclave = [clave[i] for i in PC_2] #Reordena clave de 56 a 48 bits con los elementos cuyos índices están dados por la lista PC_2.
    return nclave



def generacion_subclaves(clave):
    """ Genera 16 subclaves de 48 bits a partir de una clave inicial de 64 bits.

        Args:
            clave(list of bits): clave en binario (64 bits).

        Returns:
            nsubclave(list of lists of bits): lista con 16 listas de subclaves en binario (de 48 bits).
    """
    #print ("\n\t***Tercera parte para generación de 16 subclaves***")
    C,D = PC1(clave) #Reordena clave de 64 a 56 elementos (bits) y divide en dos.
    nc = [C] #Lista con listas de subclaves (mitad izquierda)
    nd = [D] #Lista con listas de subclaves (mitad derecha)

    # Rota a la izquierda 'i' veces la última lista de la lista de listas nc y agrega al final
    # la nueva lista rotada. (LeftShifts(16 elementos) indica el número de veces a rotar).
    for i in LeftShifts:
        nc.append(subclaves(nc[-1],i))
        nd.append(subclaves(nd[-1],i))
    
    #Para PC2
    nc.remove(C) #Elimina lista con la mitad izquierda de la clave original.
    nd.remove(D) #Elimina lista con la mitad derecha de la clave original.
    
    nsubclave = list(map(PC2,nc,nd)) #Reordena las 16 mitades de subclaves de 28 elementos (bits) a 16 subclaves de 48 bitsc/u.
    return nsubclave





#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Manipulación del mensaje~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def mensaje_bin(mensaje):
    """ Convierte una cadena de texto como mensaje a una lista en binario utilizando codificación 'utf-8'.
        Args:
            mensaje(str): mensaje a cifrar o descifrar (8 caracteres)

        Returns:
            list of bits: mensaje en binario (64 bits).
    """
    #print ("\n\t\t***Conversión de mensaje de texto a binario***")
    #texto = mensaje.encode('utf-8') #Codifica el mensaje a utf-8
    texto_bin = bin(int(mensaje,16))[2:].zfill(64) #Convierte el mensaje de hexadecimal a binario
    return list(map(int,texto_bin)) #Regresa la clave binaria en forma de lista



def IP (mensaje):
    """ Reordena los elementos de la lista 'mensaje' de 64 elementos (bits) de acuerdo al orden
        de los índices dados por la lista IP1 (que contiene 64 ínidices en desorden), y divide
        en dos el mensaje reordenado.

        Args:
            mensaje(list of bits): mensaje en binario (64 bits).

        Returns:
            I(list of bits): mitad izquierda del mensaje reordenada (32 bits).
            D(list of bits): mitad derecha del mensaje reordenado (32 bits).
    """
    #print ("\n\t***Reordenar el mensaje y separación en 32 bits***")
    mensaje.insert(0,0) #Inserta un cero al inicio de la lista para ignorar el índice cero.
    ID = [mensaje[i] for i in IP1] #Reordena el mensaje de acuerdo al orden de los índices dados por la lista IP1.
    I = ID[:32] #Se divide el mensaje reordenado en dos mitades.
    D = ID[32:]
    return I,D



def R_expand(D):
    """ Expande el mensaje de la derecha 'D' de 32 bits a otro de 48 bits de
        acuerdo al orden de los índices dados por la lista E (que contiene 48 índices).

        Args:
            D(list of bits): mitad derecha del mensaje reordenado (32 bits).

        Returns:
            nD(list of bits): mitad derecha del mensaje expandido a 48 bits.
    """
    #print ("\n\t***Reordenar 32 bits de la derecha, uso de E***")
    D.insert(0,0)
    nD = [D[i] for i in E] #Expande mensaje a 48 bits de acuerdo al orden de los índices dados por la lista E.
    return nD



def xor (a,b):
    """ Realiza la operación XOR bit a bit entre a y b.

        Args:
            a(list of bits): lista de n bits.
            b(list of bits): lista de n bits.
        
        Returns:
            list of bits: clave resultante de operar 'a XOR b' (48 bits).
    """
    #print ("\n\t\t    ***Realización de xor***")
    return list(map(lambda x,y: x^y, a,b))



def Sustitucion_S(rxor):
    """ Forma una clave de 32 bits a partir de seleccionar 8 valores de una lista S[8][4][16] que 
        contiene valores del 0 al 15, convertir dicho valor a binario (4 bits por valor) y concatenarlos.
        Los tres índices para seleccionar el valor de S surgen de:
            1) dividir la lista 'rxor' en 8 partes de 6 bits.
            2) el primer índice es la iteración actual para seleccionar cada una de las 8 partes.
            3) los otros dos índices se obtienen a partir de cada parte de 6 bits.

        Args:
            rxor(list of bits): clave de 48 bits (resultante de operar la mitad derecha del mensaje expandido con la subclave 'k').

        Returns:
            rs(list of bits): clave formada a partir de la lista S (32 bits).
    """
    #print ("\n\t\t\t***Uso la matriz S***")
    rs = ''
    ln = [rxor[i:i+6] for i in range(0,len(rxor),6)] #Divide la lista rxor en 8 partes de 6 bits
    for i in range (0,8):
        a = str(ln[i][0]) #Recupera primer elemento de la sublista
        a += str(ln[i][-1])#Concatena el último elemento de la sublista
        x = int(a,2) #Transforma a 'a' de binario a decimal
        b = ''.join(map(str, ln[i][1:5])) #Recupera elementos centrales de la sublista y los concatena
        y = int(b,2) #Transforma a 'b' de binario a decimal

        """ Selecciona elemento de S a partir de:
                - i: iteración actual (0 a 7)
                - x: valor entero obtenido del primer y ultimo bit de cada sublista de 6 bits (0 a 3)
                - y: valor entero obtenido de los 4 bits centrales de cada sublista de 6 bits (0 a 15)
            El valor seleccionado esta en el rango de 0 a 15. Se transforma a binario y se suma a
            una cadena.  Da como resultado una cadena de 32 elementos en binario.
        """
        rs += bin(S[i][x][y])[2:].zfill(4)
    rs = list(map(int,rs)) #Transforma la cadena 'rs' a una lista de enteros en binario.
    return rs



def P(rs):
    """ Reordena los elementos de la lista 'rs' de 32 bits de acuerdo al orden de los índices
        dados por la lista P1 (que contiene 32 índices en desorden).

        Args:
            rs(list of bits): clave formada a partir de la lista S (32 bits).

        Returns:
            rp(list of bits): clave reordenada (32 bits).
    """
    #print ("\n\t\t\t***Uso de la matriz P***")
    rs.insert(0,0) #Inserta un cero al inicio de la lista para ignorar el índice cero.
    rp = [rs[i] for i in P1] #Reordena la clave 'rs' de 32 bits de acuerdo al órden de los índices dados por la lista P1.
    return rp



def F(R,K):
    """ Función F del algoritmo que opera las subclaves 'k' de 48 bits con la parte derecha del mensaje de 32 bits.
        Para esto:  1) Se raliza la expanción del mensaje de 32 a 48 bits
                    2) Luego se opera bit a bit la subclave K con el mensaje mediante la función XOR
                    3) Se obtiene una nueva clave de 32 bits a partir del resultado anterior
                    4) Se reordena la nueva clave.
                    para luego poder operar bit a bit
        
        Args:
            R(list of bits): mitad derecha del mensaje reordenado (32 bits).
            K(list of bits): subclave 'k' (48 bits).

        Returns:
            rp(list of bits): clave con confusión y difusión adecuada (32 bits).
    """
    #print ("\n\t\t***Creación de función F***")
    nR = R_expand(R) #Expande el mensaje de la derecha 'R'' de 32 a 48 bits. 
    RK_xor = xor(nR,K) #Operación XOR bit a bit entre el mensaje expandido 'nR' y la subclave 'K' de 48 bits.
    rs = Sustitucion_S(RK_xor) #Obtiene clave de 32 bits a partir del resultado anterior.
    rp = P(rs) #Reordena la clave de 32 bits.
    return rp



def IP__1(ID):
    """ Reordena los elementos del la lista 'ID' de 64 bits de acuerdo al orden
        de los índices dados por la lista IP_1 (que contiene 64 ínidices en desorden).

        Args:
            ID(list of bits): mensaje en binario (64 bits).

        Returns:
            tmp(list of bits): mensaje en binario reordenado (64 bits).
    """
    #print ("\n\t\t***Uso de la matriz IP inversa***")
    ID.insert(0,0) #Inserta un cero al inicio de la lista para ignorar el índice cero.
    tmp = [ID[i] for i in IP_1] #Reordena la lista ID de acuerdo al orden de los índices dados por la lista IP_1.
    return tmp





#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Cifrado y descifrado del mensaje~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def cifrado(mensaje, key):
    """ Función que cifra un mensaje de 64 bits utilizando una clave de 64 bits mediante el algoritmo DES.

        Args:
            mensaje(str): cadena de texto del mensaje a cifrar (8 caracteres).
            key(str): cadena de texto a usar como clave de cifrado (8 caracteres ascii o 16 caracteres hexadecimales).

        Returns:
            cifrado(str): criptograma resultante (64 bits)
    """
    #print ("\n\t\t\t***Método de cifrado***")
    lr = []
    clave = clave_bin(key) #Convierte clave de hexadecimal a binario.
    msn = mensaje_bin(mensaje) #Convierte mensaje de hexadecimal a binario.
    K = generacion_subclaves(clave) #Genera 16 subclaves de 48 bits a partir de la clave de 64 bits.
    L,R = IP(msn) #Reordena el mensaje de 64 bits y lo divide en dos bloques de 32 bits.
    lr.append(L)
    lr.append(R)
    for i in range(0,16): #Se realizan 16 iteraciones para transformar el mensaje con la clave
        ff = F(lr[i+1][:],K[i])
        lr.append(xor(lr[i],ff))
    
    final = IP__1(lr[-1]+lr[-2]) #Reordena el mensaje para obtener el criptograma en binario de 64 bits
    
    a = "".join(map(str, final)) #Transforma el critpgrama de una lista con bits a una cadena en binario.

    cifrado = hex(int(a,2))[2:].zfill(16).upper() #Transforma la cadena de binario a hexadecimal y cambia a mayúsculas.
    return cifrado #Regresa el mensaje cifrado en hexadecimal



def descifrado (criptograma, key):
    """ Función que descifra un criptograma de 64 bits cifraco con DES utilizando una clave de 64 bits.
        
        Args:
            criptograma(str): cadena de texto con el criptograma a descifrar (16 caracteres hexadecimal).
            key(str): cadena de texto a usar como clave de descirado (8 caracteres ascii o 16 caracteres hexadecimales).
        Returns:
            hexadecimal(str): cadena de texto con el mensaje descrifrado en hexadecimal(8 caracteres/64 bits)
    """
    #print ("\n\t\t\t***Método de descifrado***")
    lr = []
    clave = clave_bin(key) #Convierte clave de hexadecimal a binario
    K = generacion_subclaves(clave) #Genera 16 subclaves de 48 bits a partir de la clave de 64 bits.
    K.reverse() #Invierte el orden de las listas de subclaves.
    cifrado_bin = bin(int(criptograma,16))[2::].zfill(64) #Transforma el criptograma de hexadecimal a binario.
    cifrado_bin = list(map(int,cifrado_bin))
    L,R = IP(cifrado_bin) #Reordena el mensaje de 64 bits y lo divide en dos bloques de 32 bits.
    lr.append(L)
    lr.append(R)
    for i in range (0,16): #Se realizan 16 iteraciones para transformar el criptograma con la clave
        ff = F(lr[i+1][0:],K[i])
        lr.append(xor(lr[i],ff))
    final = IP__1(lr[-1]+lr[-2]) #Reordena el criptograma para obtener el mensaje en binario de 64 bits

    a = "".join(map(str, final)) #Transforma el mensaje de una lista en bits a una cadena en binario.
    hexadecimal = hex(int(a,2))[2:].upper().zfill(16) #Transforma la cadena de binario a hexadecimal y cambia a mayúsculas.
    return hexadecimal





#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Manejo del programa~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def options():
    """ Función donde se definen las banderas a utilizar en terminal con ayuda de la librería 'optparse'.
    """
    parser = optparse.OptionParser()
    parser.add_option("-a", "--mensaje-texto", action="store", type="string", dest="mensaje_texto", 
                        help="Ingrese el mensaje a cifrar/descifrar en modo texto")
    parser.add_option("-b", "--clave-texto", dest="clave_texto", 
                        help="Ingrese la clave a utilizar para cifrar/descifrar en modo texto")
    parser.add_option("-A", "--mensaje-archivo", dest="mensaje_archivo", 
                        help="Ingrese el mensaje a cifrar/descifrar en archivo")
    parser.add_option("-B", "--clave-archivo", dest="clave_archivo", 
                        help="Ingrese la clave a utilizar para cifrar/descifrar en modo archivo")
    parser.add_option("-C", "--cifrar", action="store_true", default=False, dest="cifrar", 
                        help="Usar modo cifrado")
    parser.add_option("-D", "--descifrar", action="store_true", default=False, dest="descifrar", 
                        help="Usar modo de descifrado")
    parser.add_option("-X", "--calc-hash", action="store_true", default=False, dest="calc_hash",
                        help="Utilizado en cifrar. Indica si calcula hash SHA256 de el mensaje cifrado")
    parser.add_option("-e", "--msj-cif-hex", action="store_true", default=False, dest="msj_cif_hex", 
                        help="Utilizar en descifrado. Indica que el texto cifrado se encuentra en formato hexadecimal")
    parser.add_option("-s", "--codif-cif", action="store_true", default=False, dest="codif_base64",
                        help="Utilizado en cifrar. Indica si el mensaje a cifrar se codificará a formato Base64. Default: Hexadecimal")

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
        f = open(nombre,'r')
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
        f = open(nombre, 'w')
        f.write(datos)
        f.close()
    except:
        print("\n\t\t*** No se pudo crear el archivo "+nombre+" *** \n")
        exit()


def is_hex(s):
    """ Función que comprueba si una cadena de texto contiene solo caracteres hexadecimales.

        Args:
            s(str): Cadena de texto a comprobar

        Returns:
            bool: Indica si tiene solo caracteres hexadecimales o no
    """
    digitos_hex = set("0123456789abcdefABCDEF")
    cadena = set(s)
    return len(cadena - digitos_hex) == 0


def obtener_hash_texto(funcion, contenido):
    """ Función para obtener el hash de una cadena de texto.

        Args: 
            funcion(str): Nombre de la función hash a utilizar.
            contenido(str): Cadena de texto a cual se le calcula el hash.
    
        Returns:
            str: Cadena de texto en hexadecimal del hash obtenido.
    """
    h = hashlib.new(funcion)
    h.update(contenido.encode('utf-8'))
    return h.hexdigest()


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
        print("\n\tSin opción de difrado/descifrado.\n\tPara cifrar use la bandera -C, para descifrar la bandera -D\n")
        exit()
    elif not (options().mensaje_texto or options().mensaje_archivo):
        print("\n\tSin mensaje a cifrar/descifrar. Ingrese el mensaje usando las banderas -a o -A\n")
        exit()
    elif not (options().clave_texto or options().clave_archivo):
        print("\n\tSin clave para cifrar/descifrar. Ingrese la clave usando las banderas -b o -B\n")
        exit() 
    elif options().mensaje_texto and options().mensaje_archivo:
        print("\n\tOpciones -a y -A mutuamente excluyentes.\n")
        exit()
    elif options().clave_texto and options().clave_archivo:
        print("\n\tOpciones -b y -B mutuamente excluyentes.\n")
        exit()


    #Lectura de la mensajey clave para cifrar/descifrar
    if options().mensaje_texto: #Mensaje en texto
        mensaje = options().mensaje_texto 
    elif options().mensaje_archivo: #Mensaje en archivo
        mensaje = leer_archivo(options().mensaje_archivo)

    if options().clave_texto: #Clave en texto
        clave = options().clave_texto
    elif options().clave_archivo: #Clave en archivo
        clave = leer_archivo(options().clave_archivo)


    # Verifica que la clave tenga caracteres ascii válidos y que sea hexadecimal de 16 caracteres o 
    # ascii de 8 caracteres. Si la clave es correcta, la codifica a hexadecimal. Sino, error.
    clave = clave[:-1] if clave.endswith('\n') else clave #Elimina salto de linea del final de la clave
    try:
        clave_is_hex = is_hex(clave) #Verifica si la clave es hexadecimal

        if clave_is_hex and len(clave)==8: #La clave es ascii de 8 caracteres
            clave_cod = clave.encode('ascii').hex() #Codifica clave y transforma a hexadecimal
        elif clave_is_hex and len(clave)!=16:#La clave hexadecimal no tiene 16 caracteres
            print("\n\tClave no es de 8 caracteres ascii o 16 caracteres hexadecimales\n")
            exit()
        elif not clave_is_hex and len(clave)!=8: #La clave ascii no tiene 8 caracteres
            print("\n\tClave no es de 8 caracteres ascii o 16 caracteres hexadecimales\n")
            exit()
        elif clave_is_hex:
            clave_cod = clave #La clave ya esta en hexadecimal
        else:
            clave_cod = clave.encode('ascii').hex() #Codifica clave y transforma a hexadecimal
    except UnicodeEncodeError:
        print("\n\t\tClave con caracteres ascii inválidos\n")
        exit()
        


    #Se selecciona la bandera '-C' de cifrado
    if options().cifrar:
        msj_cod = mensaje.encode('utf-8').hex() #codifica el mensaje y transforma a hexadecimal

        #Divide mensaje hexadecimal en sublistas 64 bits (16 caracteres hexadecimales).
        mensaje_div = [msj_cod[i:i+16] for i in range(0,len(msj_cod),16)] 
        msj_cifrado = ''

        for msj in mensaje_div: #Cifrado del mensaje en bloques de 64 bits
            msj_cifrado += cifrado(msj, clave_cod)

        
        if options().codif_base64: #Si bandera -s, codifica de hex a base64, sino deja en hex
            criptograma = base64.b64encode(msj_cifrado.encode('ascii')).decode('ascii')
        else:
            criptograma = msj_cifrado


        print("\n\t\t\t*** MENSAJE CIFRADO ***\n")
        if options().mensaje_texto: #Si el mensaje se ingreso como texto, imprime mensaje (no guarda archivo).           
            print("\tMensaje: "+mensaje)
            if options().clave_texto: #Si la clave se ingreso en texto, imprime clave.
                print("\t  Clave: "+clave)
            print("\n\tCifrado: "+criptograma) #Imprime mensaje cifrado.

            if options().calc_hash: #Si bandera -X, se calcula hash del mensaje cifrado.
                hash_msj_cif=obtener_hash_texto("sha256", criptograma) #Calcula hash SHA256 del mensaje cifrado.
                print("\t   Hash: "+hash_msj_cif) #Imprime hash
            print("")

        else: #Si el mensaje está en un archivo, guarda en archivo (no imprime detos).
            name_file=options().mensaje_archivo
            name_file += "_cifrado_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S") #Nombre del archivo cifrado
            name_file_hash = name_file+'_HASH_SHA256' #Nombre del archivo del hash

            guardar_archivo(name_file, criptograma) #Guarda criptograma en archivo
            print("  Mensaje cifrado guardado en archivo: "+name_file)

            if options().calc_hash: #Si bandera -X, se calcula hash del mensaje cifrado.
                hash_msj_cif = obtener_hash_texto("sha256", criptograma) #Calcula hash SHA256 del mensaje cifrado.
                guardar_archivo(name_file_hash, hash_msj_cif) #Guarda hash en archivo
                print("               Hash SHA256 en archivo: "+name_file_hash)
            print("")
            

    #Se selecciona la bandera '-D' de descifrado
    if options().descifrar:
        #Si bandera '-e', el mensaje esta en hexadecimal. Y se comprueba que efectivamente sea hexadecimal.
        msj_is_hex = is_hex(mensaje)
        if options().msj_cif_hex and msj_is_hex:
            #Divide mensaje cifrado en hexadecimal en sublistas 64 bits (16 caracteres hexadecimales).
            mensaje_div = [mensaje[i:i+16] for i in range(0,len(mensaje),16)]
        elif options().msj_cif_hex:
            print("\n\t\tLos datos no están en hexadecimal, intentar usar sin la bandera -e\n")
            exit()

        #No bandera -e, el mensaje no esta en hexadecimal. Y se comprueba que efectivamente no sea hexadecimal.
        if not options().msj_cif_hex: 
            if msj_is_hex:
                print("\n\t\tLos datos son hexadecimales, intente usar la bandera -e\n")
                exit()

            opcion = input("\n  Se intenta descifrar datos que no se encuentran en hexadecimal, desea continuar? (Y/N): ")
            if len(opcion) == 0:
                print("\n\t\tNo se seleccionó ninguna opción.\n")
                exit()
            elif opcion.lower() == 'n':
                print("\n\t\tSe ha abortado el descifrado de los datos.\n")
                exit()
            elif opcion.lower() != 'y':
                print("\n\t\tOpcion inválida\n")
                exit()
            else:
                try:
                    cripto_hex =base64.b64decode(mensaje.encode('ascii')).decode('ascii') #Decodifica de base64 a hex
                    #Divide mensaje cifrado en hexadecimal en sublistas 64 bits (16 caracteres hexadecimales).
                    mensaje_div = [cripto_hex[i:i+16] for i in range(0,len(cripto_hex),16)]
                    for i in mensaje_div:#Verifica que cada bloque sea hexadecimal,
                        int(i,16)  #Sino es que el mensaje en base64 esta alterado, ya que no se revirtio bien a hex.
                except:
                    print("\n\t\tMensaje a descifrar con codificación inválida o alterado")
                    print("\t\t    (Solo se permite hexadecimal o base64)\n")
                    exit()

        mclaro = ''
        for msj in mensaje_div: #Descifrado del mensaje en bloques de 64 bits
            mclaro +=descifrado(msj, clave_cod)
        try:
            #mclaro = binascii.unhexlify(mclaro).decode('utf-8') #Decodifica de hexadecimal a una cadena de texto.
            mclaro = bytes.fromhex(mclaro).decode('utf-8') #Decodifica de hexadecimal a una cadena de texto.
        except:
            print("\n  El mensaje descifrado no se puede decodificar a utf-8. Se dejará en hexadecimales.")


        print("\n\t\t*** MENSAJE DESCIFRADO ***\n")
        if options().mensaje_texto: #Si el criptograma se ingreso como texto, imprime mensaje (no guarda archivo).
            print("\t\tMensaje descifrado: "+mclaro+"\n")
        else:#Si el criptograma está en un archivo, guarda en archivo (no imprime detos).
            name_file=options().mensaje_archivo
            name_file += "_descifrado_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            print("  Guardado en archivo: "+name_file+"\n")
            guardar_archivo(name_file, mclaro) #Guarda criptograma en archivo


main()
