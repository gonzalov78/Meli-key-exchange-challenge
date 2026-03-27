# Key Exchange – MercadoPago Challenge

**Autor:** Gonzalo Vigay

Implementación en Python para el intercambio seguro de claves criptográficas entre dos contrapartes financieras, siguiendo los estándares de la industria de pagos.

**Estándares implementados:**
- ANSI X9.143 – TR-31 Key Blocks
- ANSI X9.24-1 – DUKPT (Derived Unique Key Per Transaction)
- AES-256 / 2TDEA (Triple DES)
- CMAC (Cipher-based Message Authentication Code)

---

## Requisitos

- Python 3.10+
- PowerShell (Windows) o terminal Unix

```bash
pip install psec cryptography pycryptodome
```

Verificar instalación:

```bash
python --version
```

---

## Estructura del proyecto

```
key_exchange/
├── __init__.py       # package marker
├── __main__.py       # punto de entrada CLI
└── crypto_utils.py   # primitivas criptográficas
```

---

## Ejecución y resultados

### 1. Importar y validar la BDK

Desenvuelve el key block TR-31 recibido de la contraparte y valida la BDK mediante KCV.

```powershell
python -m key_exchange import-bdk `
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 `
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 `
  --kek-kcv F74B90 `
  --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 `
  --bdk-kcv EABBDC
```

**Resultado:**

```
────────────────────────────────────────────────────────────
  PASO 1 – Recombinar KEK desde los dos componentes
────────────────────────────────────────────────────────────
  KEK (hex) : C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
  KCV (CMAC): F74B90  ✓ coincide con el esperado

────────────────────────────────────────────────────────────
  PASO 2 – Desenvolver BDK del key block TR-31
────────────────────────────────────────────────────────────
  TR-31 header : D0016B0TX00E0000
  BDK (hex)    : 39EDE3A9437F3FF561898D1F6FABBD25

────────────────────────────────────────────────────────────
  PASO 3 – Validar KCV de la BDK
────────────────────────────────────────────────────────────
  KCV (3DES clásico): EABBDC  ✓ coincide con el esperado

────────────────────────────────────────────────────────────
  RESULTADO FINAL
────────────────────────────────────────────────────────────
  BDK (hex) : 39EDE3A9437F3FF561898D1F6FABBD25
  BDK KCV   : EABBDC
```

---

### 2. Generar y exportar la PEK

Genera una PEK AES-128 aleatoria y la entrega envuelta en un key block TR-31 para que la contraparte pueda verificarla por KCV.

```powershell
python -m key_exchange export-pek `
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 `
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 `
  --kek-kcv F74B90 `
  --out pek_keyblock.txt
```

**Resultado:**

```
────────────────────────────────────────────────────────────
  PASO 1 – Recombinar KEK desde los dos componentes
────────────────────────────────────────────────────────────
  KEK (hex) : C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
  KCV (CMAC): F74B90  ✓ coincide con el esperado

────────────────────────────────────────────────────────────
  PASO 2 – Generar PEK y envolver en key block TR-31
────────────────────────────────────────────────────────────
  PEK (hex)       : 8233B9DBC180CCE2B58CAFCC2E87976D
  PEK KCV (CMAC)  : A7BDDC
  TR-31 key block : D0144P0AE00E000098E717BAA07899ADCE2D48D3AF0D10C16B51133669BECB1F
                    C6AE283254F8E1119C7177F2E03F71A6739547289653D536C66DF43E98C8E6E1
                    E614A7271B2357B3
  Key block guardado en: pek_keyblock.txt

────────────────────────────────────────────────────────────
  RESULTADO FINAL
────────────────────────────────────────────────────────────
  TR-31 key block : D0144P0AE00E000098E717BAA07899ADCE2D48D3AF0D10C16B51133669BECB1F...
  PEK KCV         : A7BDDC
```

> **Nota:** La PEK se genera aleatoriamente en cada ejecución. Por diseño, el key block
> y su KCV serán distintos cada vez. Esto es el comportamiento correcto y esperado.

---

### 3. DUKPT – Descifrar mensaje (Bonus)

Deriva la session key a partir de la BDK y el KSN mediante el algoritmo NRKGP
(ANSI X9.24-1) y descifra el mensaje cifrado con 3DES-ECB.

```powershell
python -m key_exchange dukpt-decrypt `
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 `
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 `
  --kek-kcv F74B90 `
  --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 `
  --bdk-kcv EABBDC `
  --ksn 729C77361E9A51E000F2 `
  --ciphertext FCC832A91953151148E86A01BE9420AC
```

**Resultado:**

```
────────────────────────────────────────────────────────────
  PASO 1 – Recombinar KEK desde los dos componentes
────────────────────────────────────────────────────────────
  KEK (hex) : C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
  KCV (CMAC): F74B90  ✓ coincide con el esperado

────────────────────────────────────────────────────────────
  BONUS – Derivación DUKPT y descifrado
────────────────────────────────────────────────────────────
  BDK (hex)  : 39EDE3A9437F3FF561898D1F6FABBD25 | KCV: EABBDC  ✓
  KSN        : 729C77361E9A51E000F2
  Ciphertext : FCC832A91953151148E86A01BE9420AC
  Plaintext  : 'MELI_Rocks!'
```

---

## Flujo general

```
Componente 1 ──┐
               ├─ XOR ──► KEK ──► validar CMAC-KCV
Componente 2 ──┘                        │
                                         ▼
                              unwrap TR-31 ──► BDK ──► validar KCV clásico (3DES)
                                         │
                                         └──► DUKPT: BDK + KSN ──► session key ──► decrypt
                              
                              generate PEK ──► wrap TR-31 ──► entregar a contraparte
```

---

## Preguntas teóricas

**1. ¿Podrían enviarse los dos componentes de la KEK por el mismo canal?**

No. El propósito del split es el "dual control": ningún custodio por sí solo puede reconstruir la KEK. Si ambos componentes viajan por el mismo canal y ese canal es comprometido, el atacante obtiene ambos componentes y puede reconstruir la KEK con un XOR trivial. El modelo de seguridad exige que comprometer un único canal no sea suficiente.

**2. ¿Qué método alternativo existe para entregar la KEK sin que viaje entera?**

Varias opciones según el nivel de infraestructura disponible:

- **Cifrado asimétrico:** la contraparte cifra la KEK con la clave pública del receptor. La KEK nunca viaja en claro; solo el poseedor de la clave privada puede recuperarla. Requiere PKI.
- **Key Ceremony presencial:** cada componente es transportado físicamente por un custodio distinto, bajo procedimiento notariado. Es el estándar PCI para HSMs de producción.
- **Shamir's Secret Sharing (M-de-N):** se generan N shares y se necesitan M para reconstruir la KEK, tolerando la pérdida de hasta N-M custodios sin comprometer la seguridad.

**3. ¿Queda comprometida la KEK si se compromete uno o ambos custodios?**

| Escenario | Resultado |
|---|---|
| Un custodio comprometido | **KEK segura.** El componente expuesto es un bloque de bytes aleatorios que no revela información sobre la KEK — equivalente teórico al one-time pad. |
| Ambos custodios comprometidos | **KEK comprometida.** Con los dos componentes el atacante reconstruye la KEK con XOR en milisegundos. Todas las llaves protegidas por ella deben rotarse de inmediato. |

---

## Decisiones de diseño

**Uso de psec para TR-31**
Se eligió la librería `psec` para el manejo de key blocks en lugar de una implementación manual. En un entorno de seguridad profesional, el parseo manual de formatos binarios es fuente frecuente de vulnerabilidades. Delegar esto a una librería testeada garantiza la integridad del proceso.

**DUKPT implementado desde la especificación**
La librería `dukpt` v1.0.1 (recomendada en el enunciado) tiene un bug que provoca `AttributeError` al invocar `gen_key()`. Se implementó el algoritmo NRKGP directamente siguiendo la especificación ANSI X9.24-1 Anexo A, con el IPEK validado contra los vectores de prueba oficiales del estándar.

**Visibilidad de llaves en consola**
En producción, las llaves nunca se imprimirían en texto claro. Para este challenge se mantiene la salida visible para facilitar la validación y trazabilidad del flujo por parte del evaluador. En un sistema real, estas operaciones se realizarían dentro de un HSM o enclave seguro.

**Metodología**
Se utilizaron herramientas de IA y documentación técnica oficial (ANSI X9.24-1, ANSI X9.143) para acelerar la comprensión de los protocolos. La arquitectura final es modular, cada función tiene una única responsabilidad, y el flujo completo es auditable paso a paso.
