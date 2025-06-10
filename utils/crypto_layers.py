import os
import base64
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# --- Configuración ---
ITERACIONES = 100_000
TAMANO_CLAVE = 32
backend = default_backend()

# --- Derivar clave desde contraseña y salt ---
def derivar_clave(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=TAMANO_CLAVE,
        salt=salt,
        iterations=ITERACIONES,
        backend=backend
    )
    return kdf.derive(password.encode())

# ---INICIO DE FUNCIONES PARA EL CIFRADO
def cifrar_texto(texto: str, password: str) -> str:
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)  # ChaCha20
    clave_chacha = derivar_clave(password, salt)

    # 1️ Cifrado con ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(clave_chacha)
    cifrado_chacha = chacha.encrypt(nonce, texto.encode(), None)

    # 2️ Cifrado con Blowfish (modo CBC)
    iv = get_random_bytes(8)  # Blowfish usa bloques de 8 bytes
    clave_blowfish = derivar_clave(password[::-1], salt[::-1])[:16]  # Blowfish soporta hasta 448 bits, tomamos 128 bits
    cipher2 = Blowfish.new(clave_blowfish, Blowfish.MODE_CBC, iv)

    # Padding manual (a múltiplos de 8 bytes)
    padding_len = 8 - len(cifrado_chacha) % 8
    padded = cifrado_chacha + bytes([padding_len]) * padding_len
    cifrado_blowfish = cipher2.encrypt(padded)

    # 3️ Codificación final
    datos_finales = salt + nonce + iv + cifrado_blowfish
    return base64.a85encode(datos_finales).decode()

# --- DECIFRADO - PROCESO INVERSO----------------
def descifrar_texto(cifrado_base85: str, password: str) -> str:
    try:
        cifrado_base85 = cifrado_base85.strip().replace('\n', '').replace('\r', '')

        datos = base64.a85decode(cifrado_base85.encode())
        salt = datos[:16]
        nonce = datos[16:28]
        iv = datos[28:36]
        cifrado_blowfish = datos[36:]

        # Blowfish descifrado
        clave_blowfish = derivar_clave(password[::-1], salt[::-1])[:16]
        cipher2 = Blowfish.new(clave_blowfish, Blowfish.MODE_CBC, iv)
        chacha_encrypted_padded = cipher2.decrypt(cifrado_blowfish)

        padding_len = chacha_encrypted_padded[-1]
        chacha_encrypted = chacha_encrypted_padded[:-padding_len]

        # ChaCha20 descifrado
        clave_chacha = derivar_clave(password, salt)
        chacha = ChaCha20Poly1305(clave_chacha)
        texto = chacha.decrypt(nonce, chacha_encrypted, None).decode()
        return texto

    except Exception as e:
        return f"❌ Error de descifrado: {str(e)}"


    