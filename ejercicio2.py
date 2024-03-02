import Crypto
from Crypto.Util.number import long_to_bytes
from Crypto import Random
import hashlib


# Números de bits:
bits = 1024
e = 65537

# ELIGE DOS NUMERO PRIMOS GRANDES P y Q DE FORMA ALEATORIA
# Alice
p_alice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
q_alice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Bob
p_ac = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
q_ac = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# 2 CALCULAR LA LLAVE PUBLICA
# Alice
n_alice = p_alice * q_alice
# AC
n_ac = p_ac * q_ac

# 3 SACO EL NUMERO DE PHI 
# Alice
phi_alice = (p_alice - 1) * (q_alice - 1)
# AC
phi_ac = (p_ac - 1) * (q_ac - 1)


# 4 CALCULAR LLAVE PRIVADA
# Alice
d_alice = Crypto.Util.number.inverse(e, phi_alice)
# Bob
d_ac = Crypto.Util.number.inverse(e, phi_ac)

# Ciframos el mensaje:

mensaje_hash = hashlib.sha256(b"Hola").hexdigest()
print("_______________________________________________________________________________")
print("|                                                                             |")
print(f"HASH ORIGINAL: {mensaje_hash}")
print("|_____________________________________________________________________________|")
mensaje_numero = int.from_bytes(mensaje_hash.encode('utf-8'), byteorder='big')
print(f"Mensaje a numero: {mensaje_numero}")


# PRIMERA FIRMA

# 5 FIRMA (alice esta firmano con su llave privada)
c = pow(mensaje_numero, d_alice, n_alice)
print(f"MENSAJE FIRMADO (ALICE): \n{c}")


# DESCIFRANDO

d = pow(c, e, n_alice)
print(f"MENSAJE DESCENCRIPTADO (ALICE): \n{d}")

# PASANDO A TEXTO
mensaje_descifrado = int.to_bytes(d, d.bit_length(), byteorder='big').decode('utf-8')
print("_________________________________________________________________________________________")
print("|                                                                                       |")
print(f"HASH COMPROBADO (ALICE): {mensaje_descifrado}")
print("|_______________________________________________________________________________________|")

# SEGUNDA FIRMA

# 5 FIRMA (ac  esta firmano con su llave privada)
c_ac = pow(d, d_ac, n_ac)
print(f"MENSAJE FIRMADO (AC): \n{c_ac}")


# DESCIFRANDO

d_ac = pow(c_ac, e, n_ac)
print(f"MENSAJE DESCENCPRITADO (AC): \n{d_ac}")

# PASANDO A TEXTO
mensaje_descifrado_ac = int.to_bytes(d_ac, d_ac.bit_length(), byteorder='big').decode('utf-8')
print("______________________________________________________________________________________")
print("|                                                                                    |")
print(f"HASH COMPROBADO (AC): {mensaje_descifrado_ac}")
print("|____________________________________________________________________________________|")