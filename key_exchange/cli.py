"""
cli.py
Interfaz de línea de comandos para el intercambio de llaves con la contraparte.

Comandos disponibles:
  export-pek   Genera una PEK aleatoria y la entrega en un key block TR-31.
  import-bdk   Recibe el key block TR-31 de la BDK, lo desenvuelve y valida.

Uso:
  python -m key_exchange export-pek \\
      --kek-component-1 <hex o archivo> \\
      --kek-component-2 <hex o archivo> \\
      --kek-kcv <KCV esperado> \\
      --out <archivo de salida>

  python -m key_exchange import-bdk \\
      --kek-component-1 <hex o archivo> \\
      --kek-component-2 <hex o archivo> \\
      --kek-kcv <KCV esperado> \\
      --bdk-keyblock <TR-31 o archivo> \\
      --bdk-kcv <KCV esperado>
"""

import argparse
import os
import sys

from .crypto_utils import (
    reconstruir_kek,
    calcular_kcv_cmac,
    calcular_kcv_clasico,
    generar_pek,
    wrap_pek,
    unwrap_keyblock,
    decrypt_dukpt,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers de I/O
# ──────────────────────────────────────────────────────────────────────────────

def _leer_valor(valor: str) -> str:
    """
    Acepta un valor hex directo o una ruta de archivo que lo contiene.
    Útil para que los componentes de la KEK puedan pasarse como archivos
    físicos (custodiados por personas distintas) o inline en el comando.
    """
    if len(valor) <= 512 and os.path.isfile(valor):
        with open(valor) as f:
            return f.read().strip()
    return valor.strip()


def _seccion(titulo: str) -> None:
    """Imprime un separador visual para facilitar la lectura de la salida."""
    print(f"\n{'─' * 60}")
    print(f"  {titulo}")
    print(f"{'─' * 60}")


# ──────────────────────────────────────────────────────────────────────────────
# Paso común: reconstruir y validar la KEK
# ──────────────────────────────────────────────────────────────────────────────

def _reconstruir_y_validar_kek(args: argparse.Namespace) -> bytes:
    """
    Recombina los dos componentes por XOR y verifica el CMAC-KCV resultante.
    Interrumpe la ejecución si el KCV no coincide, evitando operar con una
    KEK incorrecta (por ejemplo, si un componente fue transmitido con errores).
    """
    _seccion("PASO 1 – Recombinar KEK desde los dos componentes")

    comp1 = _leer_valor(args.kek_component_1)
    comp2 = _leer_valor(args.kek_component_2)

    kek = reconstruir_kek(comp1, comp2)
    kcv_calculado = calcular_kcv_cmac(kek)

    if kcv_calculado != args.kek_kcv.upper():
        print(
            f"[ERROR] KCV de KEK no coincide: "
            f"calculado={kcv_calculado}, esperado={args.kek_kcv.upper()}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  KEK (hex) : {kek.hex().upper()}")
    print(f"  KCV (CMAC): {kcv_calculado}  ✓ coincide con el esperado")
    return kek


# ──────────────────────────────────────────────────────────────────────────────
# Comando: export-pek
# ──────────────────────────────────────────────────────────────────────────────

def cmd_export_pek(args: argparse.Namespace) -> None:
    """
    Genera una PEK aleatoria AES-128 y la entrega envuelta en un key block TR-31.

    La contraparte podrá desenvolver el key block usando la misma KEK y
    verificar la integridad de la PEK recibida con el KCV que se imprime.
    """
    kek = _reconstruir_y_validar_kek(args)

    _seccion("PASO 2 – Generar PEK y envolver en key block TR-31")

    pek       = generar_pek()
    keyblock  = wrap_pek(kek, pek)
    kcv_pek   = calcular_kcv_cmac(pek)

    print(f"  PEK (hex)       : {pek.hex().upper()}")
    print(f"  PEK KCV (CMAC)  : {kcv_pek}")
    print(f"  TR-31 key block : {keyblock}")

    # Si se indicó archivo de salida, persistir el key block
    if args.out:
        with open(args.out, "w") as f:
            f.write(keyblock)
        print(f"\n  Key block guardado en: {args.out}")

    _seccion("RESULTADO FINAL")
    print(f"  TR-31 key block : {keyblock}")
    print(f"  PEK KCV         : {kcv_pek}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Comando: import-bdk
# ──────────────────────────────────────────────────────────────────────────────

def cmd_import_bdk(args: argparse.Namespace) -> None:
    """
    Desenvuelve el key block TR-31 recibido de la contraparte y valida la BDK.

    La BDK es una llave 2TDEA (Triple-DES de 16 bytes). Su KCV se calcula
    con el método clásico (3DES-ECB sobre ceros) en lugar de CMAC, porque
    es el estándar vigente para llaves TDES en esquemas DUKPT.
    """
    kek = _reconstruir_y_validar_kek(args)

    _seccion("PASO 2 – Desenvolver BDK del key block TR-31")

    keyblock_raw = _leer_valor(args.bdk_keyblock)

    try:
        header, bdk = unwrap_keyblock(kek, keyblock_raw)
    except Exception as exc:
        print(f"[ERROR] No se pudo desenvolver el key block: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  TR-31 header : {header}")
    print(f"  BDK (hex)    : {bdk.hex().upper()}")

    _seccion("PASO 3 – Validar KCV de la BDK")

    kcv_calculado = calcular_kcv_clasico(bdk)

    if kcv_calculado != args.bdk_kcv.upper():
        print(
            f"[ERROR] KCV de BDK no coincide: "
            f"calculado={kcv_calculado}, esperado={args.bdk_kcv.upper()}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  KCV (3DES clásico): {kcv_calculado}  ✓ coincide con el esperado")

    _seccion("RESULTADO FINAL")
    print(f"  BDK (hex) : {bdk.hex().upper()}")
    print(f"  BDK KCV   : {kcv_calculado}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Comando: dukpt-decrypt  (BONUS)
# ──────────────────────────────────────────────────────────────────────────────

def cmd_dukpt_decrypt(args: argparse.Namespace) -> None:
    """
    BONUS: descifra un mensaje cifrado con DUKPT 3DES-ECB.

    Flujo:
      1. Reconstruir y validar la KEK.
      2. Desenvolver y validar la BDK.
      3. Derivar la session key DUKPT (BDK + KSN) usando el NRKGP.
      4. Descifrar el ciphertext con 3DES-ECB.
    """
    kek = _reconstruir_y_validar_kek(args)

    keyblock_raw = _leer_valor(args.bdk_keyblock)
    try:
        _, bdk = unwrap_keyblock(kek, keyblock_raw)
    except Exception as exc:
        print(f"[ERROR] No se pudo desenvolver la BDK: {exc}", file=sys.stderr)
        sys.exit(1)

    kcv_bdk = calcular_kcv_clasico(bdk)
    if kcv_bdk != args.bdk_kcv.upper():
        print(f"[ERROR] KCV de BDK no coincide: {kcv_bdk} != {args.bdk_kcv.upper()}", file=sys.stderr)
        sys.exit(1)

    _seccion("BONUS – Derivación DUKPT y descifrado")

    print(f"  BDK (hex) : {bdk.hex().upper()} | KCV: {kcv_bdk}  ✓")
    print(f"  KSN       : {args.ksn.upper()}")

    plaintext = decrypt_dukpt(bdk.hex(), args.ksn, args.ciphertext)

    print(f"  Ciphertext : {args.ciphertext.upper()}")
    print(f"  Plaintext  : '{plaintext}'")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Parser de argumentos
# ──────────────────────────────────────────────────────────────────────────────

def _agregar_args_kek(parser: argparse.ArgumentParser) -> None:
    """Agrega los argumentos de KEK compartidos por todos los subcomandos."""
    parser.add_argument(
        "--kek-component-1", required=True, metavar="HEX_O_ARCHIVO",
        help="Componente 1 de la KEK (64 hex chars) o ruta al archivo que lo contiene",
    )
    parser.add_argument(
        "--kek-component-2", required=True, metavar="HEX_O_ARCHIVO",
        help="Componente 2 de la KEK (64 hex chars) o ruta al archivo que lo contiene",
    )
    parser.add_argument(
        "--kek-kcv", required=True, metavar="KCV",
        help="KCV esperado de la KEK (6 hex chars, CMAC-AES)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m key_exchange",
        description="Intercambio de llaves criptográficas – MercadoPago challenge",
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    # ── export-pek ──────────────────────────────────────────────────
    p_exp = sub.add_parser("export-pek", help="Genera PEK y la exporta en TR-31")
    _agregar_args_kek(p_exp)
    p_exp.add_argument(
        "--out", metavar="ARCHIVO", default=None,
        help="(Opcional) archivo donde guardar el key block TR-31 de la PEK",
    )
    p_exp.set_defaults(func=cmd_export_pek)

    # ── import-bdk ──────────────────────────────────────────────────
    p_imp = sub.add_parser("import-bdk", help="Desenvuelve y valida la BDK desde TR-31")
    _agregar_args_kek(p_imp)
    p_imp.add_argument(
        "--bdk-keyblock", required=True, metavar="TR31_O_ARCHIVO",
        help="Key block TR-31 de la BDK o ruta al archivo que lo contiene",
    )
    p_imp.add_argument(
        "--bdk-kcv", required=True, metavar="KCV",
        help="KCV esperado de la BDK (6 hex chars, 3DES clásico)",
    )
    p_imp.set_defaults(func=cmd_import_bdk)

    # ── dukpt-decrypt (BONUS) ────────────────────────────────────────
    p_dkpt = sub.add_parser("dukpt-decrypt", help="BONUS: descifra mensaje DUKPT 3DES")
    _agregar_args_kek(p_dkpt)
    p_dkpt.add_argument("--bdk-keyblock", required=True, metavar="TR31_O_ARCHIVO")
    p_dkpt.add_argument("--bdk-kcv",      required=True, metavar="KCV")
    p_dkpt.add_argument("--ksn",          required=True, metavar="HEX",
                        help="Key Serial Number (20 hex chars, 10 bytes)")
    p_dkpt.add_argument("--ciphertext",   required=True, metavar="HEX",
                        help="Ciphertext a descifrar en hexadecimal")
    p_dkpt.set_defaults(func=cmd_dukpt_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    args.func(args)
