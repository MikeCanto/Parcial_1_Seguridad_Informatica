# Ejercicio 1
import Crypto.Util.number
import Crypto
import hashlib
from itertools import islice

n_bits = 1024
e = 65537

# CALCULAMOS PRIMOS
# Alice
p_alice = Crypto.Util.number.getPrime(n_bits, randfunc=Crypto.Random.get_random_bytes)
q_alice = Crypto.Util.number.getPrime(n_bits, randfunc=Crypto.Random.get_random_bytes)
# Bob
p_bob = Crypto.Util.number.getPrime(n_bits, randfunc=Crypto.Random.get_random_bytes)
q_bob = Crypto.Util.number.getPrime(n_bits, randfunc=Crypto.Random.get_random_bytes)


# CALCULAMOS LLAVE PUBLICA
# Alice
llave_pub_alice = p_alice * q_alice
# Bob
llave_pub_bob = p_bob * q_bob


# CALCULAMOS PHI
# Alice
phi_alice = (p_alice-1)*(q_alice-1)
# Bob
phi_bob = (p_bob-1)*(q_bob-1)


# CALCULAMOS LA LLAVE PRIVADA
# Alice
llave_pri_alice = Crypto.Util.number.inverse(e, phi_alice)
# Bob
llave_pri_bob = (Crypto.Util.number.inverse(e, phi_bob))


# CIFRAMOS EL MENSAJE
mensaje = "Muy lejos, más allá de las montañas de palabras, alejadoes de les y las consonantes, viven los textos simulados. Viven aislados en casas de letras, en la costa de la semántica, un gran océano de lenguas. Un riachuelo llamado Pons fluye por su pueblo y los abastece con las normas necesarias. Hablamos de un país paraisomático en el que a uno le caen pedazos de frases asadas en la boca. Ni siquiera los todopoderosos signos de puntuación dominan a los textos simulados; una vida, se puede decir, poco ortográfica. Pero un buen día, una pequeña línea de texto simulado, llamada Lorem Ipsum, decidió aventurarse y salir al vasto mundo de la gramática. El gran Oxmox le desanconsejó hacerlo, ya que esas tierras estaban llenas de comas malvadas, signos de interrogación salvajes y puntos y coma traicioneros, pero el texto simulado no se dejó atemorizar. Empacó sus siete versales, enfundó su inicial en el cinturón y se puso en camino. Cuando ya había escalado las primeras colinas de las montañas cursivas, se dio media vuelta pa"
print(f"\n\nMENSAJE ORIGINAL: \n {mensaje}\n\n")


# DIVIDIMOS EN PARTES DE 128
mensaje_div = ["".join(islice(mensaje, i, i + 128)) for i in range(0, len(mensaje), 128)]


# CONVERTIMOS EL MENSAJE A BITS
m = [int.from_bytes(part.encode("utf-8"), byteorder="big") for part in mensaje_div]


# CIFRAMOS EL MENSAJE
mensaje_cifrado = [pow(part, e, llave_pub_bob) for part in m]
print(f"MENSAJE CIFRADO: \n{mensaje_cifrado}\n\n")

# DESCIFRAMOS EL MENSAJE
des = [pow(part, llave_pri_bob, llave_pub_bob) for part in mensaje_cifrado]


# CONVERTIMOS EL MENSAJE DECIFRADO DE BITS A CARACTERES
final_parts = [part.to_bytes((part.bit_length() + 7) // 8, byteorder="big").decode("utf-8") for part in des]

# UNIMOS OTRA VEZ EL MENSAJE  
decrypted_message = "".join(final_parts)
print("MENSAJE UNIDO: \n", decrypted_message, "\n\n")

# COMPARAMOS LOS HASHES
msg_hash = hashlib.sha256(mensaje.encode()).hexdigest()
decrypted_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()

# IMPRIMIRMOS LOS HASH
print(f"HASH ORIGINAL: \n{msg_hash}")
print(f"HASH DECIFRADO: \n{decrypted_hash}\n\n")

