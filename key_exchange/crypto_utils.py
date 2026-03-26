"""
crypto_utils.py
Primitivas criptográficas para el intercambio de llaves entre contrapartes.

Cubre:
  - Recombinación de componentes KEK por XOR
  - Cálculo de KCV (CMAC-AES para KEK/PEK, clásico 3DES para BDK)
  - Generación y envoltura de PEK en key block TR-31
  - Desenvoltura de key blocks TR-31
  - Derivación de session key DUKPT (ANSI X9.24-1) y descifrado 3DES-ECB

Librerías utilizadas:
  - pycryptodome : operaciones simétricas (AES, DES, 3DES, CMAC)
  - psec         : estándar TR-31 / ANSI X9.143
"""

from Crypto.Hash   import CMAC
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
import psec.tr31


# ──────────────────────────────────────────────────────────────────────────────
# Utilidad interna
# ──────────────────────────────────────────────────────────────────────────────

def _xor(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte entre dos cadenas de igual longitud."""
    return bytes(x ^ y for x, y in zip(a, b))


# ──────────────────────────────────────────────────────────────────────────────
# KEK – Key Encryption Key
# ──────────────────────────────────────────────────────────────────────────────

def reconstruir_kek(comp1_hex: str, comp2_hex: str) -> bytes:
    """
    Recombina los dos componentes de la KEK mediante XOR.

    El split en dos componentes garantiza dual control: ningún custodio
    individual posee la KEK completa. Con un único componente no se puede
    deducir nada sobre la llave resultante (equivalente al one-time pad).

    Parámetros
    ----------
    comp1_hex, comp2_hex : strings hexadecimales de 64 caracteres (32 bytes c/u)

    Retorna
    -------
    kek : 32 bytes (AES-256)
    """
    return _xor(bytes.fromhex(comp1_hex), bytes.fromhex(comp2_hex))


def calcular_kcv_cmac(clave: bytes) -> str:
    """
    Calcula el CMAC-KCV para llaves AES (usado en KEK y PEK).

    Procedimiento: AES-CMAC(clave, 0x00 * 16), retorna los primeros 3 bytes
    en hexadecimal mayúscula. Definido en ANSI X9.143 para key blocks versión D.

    Parámetros
    ----------
    clave : llave AES (16, 24 o 32 bytes)

    Retorna
    -------
    kcv : 6 caracteres hexadecimales en mayúscula (ej. 'F74B90')
    """
    cmac = CMAC.new(clave, ciphermod=AES)
    cmac.update(b'\x00' * 16)
    return cmac.digest()[:3].hex().upper()


# ──────────────────────────────────────────────────────────────────────────────
# BDK – Base Derivation Key
# ──────────────────────────────────────────────────────────────────────────────

def calcular_kcv_clasico(clave: bytes) -> str:
    """
    Calcula el KCV clásico para llaves 2TDEA (método heredado, usado en BDK).

    Procedimiento: 3DES-ECB(clave, 0x00 * 8), retorna los primeros 3 bytes.
    A diferencia del CMAC-KCV, opera sobre 8 bytes de cero con 3DES. Este
    método se mantiene para llaves Triple-DES por compatibilidad con HSMs legacy.

    Parámetros
    ----------
    clave : llave 2TDEA de 16 bytes

    Retorna
    -------
    kcv : 6 caracteres hexadecimales en mayúscula (ej. 'EABBDC')
    """
    clave_24 = clave + clave[:8]   # expansión 2TDEA → 3TDEA (EDE)
    cifrador = DES3.new(clave_24, DES3.MODE_ECB)
    return cifrador.encrypt(b'\x00' * 8)[:3].hex().upper()


# ──────────────────────────────────────────────────────────────────────────────
# PEK – PIN Encryption Key
# ──────────────────────────────────────────────────────────────────────────────

def generar_pek() -> bytes:
    """
    Genera una PEK aleatoria de 16 bytes (AES-128) criptográficamente segura.

    Retorna
    -------
    pek : 16 bytes aleatorios
    """
    return get_random_bytes(16)


def wrap_pek(kek: bytes, pek: bytes) -> str:
    """
    Envuelve la PEK en un key block TR-31 usando la KEK como llave de protección.

    Header utilizado: D0000P0AE00E0000
      D  → versión D (AES Key Derivation Binding Method, ANSI X9.143)
      P0 → PIN Encryption Key
      A  → algoritmo AES
      E  → modo de uso: Encrypt/Decrypt
      E  → exportable bajo KEK

    Parámetros
    ----------
    kek : 32 bytes (AES-256), llave de transporte
    pek : 16 bytes (AES-128), llave a envolver

    Retorna
    -------
    key_block : string TR-31 listo para enviar a la contraparte
    """
    header = "D0000P0AE00E0000"
    kb = psec.tr31.KeyBlock(kbpk=kek, header=header)
    return kb.wrap(key=pek)


# ──────────────────────────────────────────────────────────────────────────────
# TR-31 – Desenvoltura genérica
# ──────────────────────────────────────────────────────────────────────────────

def unwrap_keyblock(kek: bytes, keyblock: str) -> tuple:
    """
    Desenvoltura genérica de un key block TR-31.

    Valida la autenticidad del bloque (MAC interno) antes de descifrar.
    Si la KEK es incorrecta o el bloque fue alterado, lanza excepción.

    Parámetros
    ----------
    kek      : llave de transporte (KBPK)
    keyblock : string TR-31

    Retorna
    -------
    (header, key) : tupla con el header parseado y los bytes de la llave
    """
    return psec.tr31.unwrap(kbpk=kek, key_block=keyblock)


# ──────────────────────────────────────────────────────────────────────────────
# DUKPT – Derived Unique Key Per Transaction  (ANSI X9.24-1, TDES)
# ──────────────────────────────────────────────────────────────────────────────

def _nrkgp(curkey: bytes, r8: bytes) -> bytes:
    """
    Non-Reversible Key Generation Process (ANSI X9.24-1 Annex A §A.6).

    Dado el working key actual (16 bytes) y el registro r8 (8 bytes),
    produce una nueva llave de 16 bytes. El proceso usa DES simple
    (no 3DES) para el cifrado interno, con una clave variante para
    calcular la mitad izquierda.

    Derivación:
      variant       = curkey XOR C0C0C0C000000000C0C0C0C000000000
      nueva mitad derecha = DES_enc(curkey[0:8], r8 XOR curkey[8:16]) XOR curkey[8:16]
      nueva mitad izq.   = DES_enc(variant[0:8], r8 XOR variant[8:16]) XOR variant[8:16]
      nueva clave        = mitad_izq || mitad_der
    """
    MASK_VARIANTE = bytes.fromhex("C0C0C0C000000000C0C0C0C000000000")
    variante = _xor(curkey, MASK_VARIANTE)

    # Mitad derecha: usa la clave original
    nueva_der = _xor(
        DES.new(curkey[:8], DES.MODE_ECB).encrypt(_xor(r8, curkey[8:])),
        curkey[8:]
    )
    # Mitad izquierda: usa la clave variante
    nueva_izq = _xor(
        DES.new(variante[:8], DES.MODE_ECB).encrypt(_xor(r8, variante[8:])),
        variante[8:]
    )

    return nueva_izq + nueva_der


def derivar_ipek(bdk: bytes, ksn: bytes) -> bytes:
    """
    Deriva el IPEK (Initial PIN Encryption Key) a partir de la BDK y el KSN.

    El IPEK es único por terminal (determinado por la parte fija del KSN).
    Se calcula cifrando los primeros 8 bytes del KSN base con 3DES, usando
    la BDK original para la mitad izquierda y la BDK con máscara variante
    para la mitad derecha.

    Parámetros
    ----------
    bdk : 16 bytes, Base Derivation Key (2TDEA)
    ksn : 10 bytes, Key Serial Number

    Retorna
    -------
    ipek : 16 bytes
    """
    # Zerear los 21 bits del contador (últimos 21 bits del KSN)
    ksn_int  = int.from_bytes(ksn, 'big')
    ksn_base = (ksn_int & ~0x1FFFFF).to_bytes(10, 'big')
    ksn8     = ksn_base[:8]

    bdk_24   = bdk + bdk[:8]   # expansión 2TDEA → 3TDEA

    ipek_izq = DES3.new(bdk_24, DES3.MODE_ECB).encrypt(ksn8)

    # Variante de la BDK: XOR con la máscara estándar DUKPT
    MASK_VARIANTE = bytes.fromhex("C0C0C0C000000000C0C0C0C000000000")
    bdk_variante  = _xor(bdk, MASK_VARIANTE)
    bdk_var_24    = bdk_variante + bdk_variante[:8]

    ipek_der = DES3.new(bdk_var_24, DES3.MODE_ECB).encrypt(ksn8)

    return ipek_izq + ipek_der


def derivar_session_key(bdk: bytes, ksn: bytes) -> bytes:
    """
    Deriva la session key (future key) DUKPT para un KSN dado.

    Algoritmo (ANSI X9.24-1 Annex A):
      1. Derivar el IPEK desde BDK + KSN base.
      2. Inicializar el registro r8 con los bytes 2-9 del KSN (contador zeroed).
      3. Recorrer los 21 bits del contador del KSN de MSB a LSB.
         Por cada bit en 1: actualizar r8 y aplicar NRKGP al working key.

    Cada transacción usa una llave diferente; comprometer una no expone
    las anteriores ni las siguientes (forward secrecy limitada).

    Parámetros
    ----------
    bdk : 16 bytes, Base Derivation Key
    ksn : 10 bytes, Key Serial Number (incluye el contador de transacción)

    Retorna
    -------
    session_key : 16 bytes
    """
    ipek = derivar_ipek(bdk, ksn)

    ksn_int  = int.from_bytes(ksn, 'big')
    ksnr_int = ksn_int & 0xFFFFFFFFFFFFFFFF   # bytes 2-9 del KSN
    contador = ksnr_int & 0x1FFFFF             # 21 bits del contador de transacción
    r8_int   = ksnr_int & ~0x1FFFFF            # registro r8, contador zeroed

    curkey = ipek
    bit    = 0x100000   # MSB del contador de 21 bits

    while bit > 0:
        if contador & bit:
            r8_int |= bit
            curkey  = _nrkgp(curkey, r8_int.to_bytes(8, 'big'))
        bit >>= 1

    return curkey


def decrypt_dukpt(bdk_hex: str, ksn_hex: str, ciphertext_hex: str) -> str:
    """
    Descifra un mensaje cifrado con 3DES-ECB usando la llave DUKPT correspondiente.

    Flujo completo:
      BDK + KSN → IPEK → session key (NRKGP) → 3DES-ECB decrypt → plaintext

    Parámetros
    ----------
    bdk_hex        : BDK en hexadecimal (32 chars, 16 bytes)
    ksn_hex        : KSN en hexadecimal (20 chars, 10 bytes)
    ciphertext_hex : ciphertext en hexadecimal

    Retorna
    -------
    plaintext : string, con padding de ceros removido
    """
    bdk        = bytes.fromhex(bdk_hex)
    ksn        = bytes.fromhex(ksn_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    session_key = derivar_session_key(bdk, ksn)

    # Expansión 2TDEA → 3TDEA para DES3 de pycryptodome
    session_key_24 = session_key + session_key[:8]

    plaintext = DES3.new(session_key_24, DES3.MODE_ECB).decrypt(ciphertext)

    return plaintext.decode(errors="ignore").rstrip('\x00')
