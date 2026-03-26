# Key Exchange – MercadoPago Challenge

Autor: Gonzalo Vigay

Implementación en Python para intercambio seguro de claves criptográficas utilizando:

- ANSI X9.143 (TR-31 Key Blocks)
- DUKPT (ANSI X9.24)
- AES / 3DES
- CMAC

---

# Requisitos

- Windows
- PowerShell
- Python 3.10+

Verificar instalación:

python --version

---

# Uso

Ejecutar los comandos desde la carpeta raíz del proyecto.

Exportar PEK

Genera una PEK y la devuelve en formato TR-31:

python -m key_exchange export-pek --kek-component-1 <hex> --kek-component-2 <hex> --kek-kcv <kcv> --out pek.txt

------------------------------------------------------------

Importar BDK

Desenvuelve un key block TR-31 y valida su KCV:

python -m key_exchange import-bdk --kek-component-1 <hex> --kek-component-2 <hex> --kek-kcv <kcv> --bdk-keyblock <keyblock> --bdk-kcv <kcv>

------------------------------------------------------------

DUKPT Decrypt (Bonus)

Descifra un mensaje usando DUKPT:

python -m key_exchange dukpt-decrypt --bdk <bdk> --ksn <ksn> --ciphertext <data>

------------------------------------------------------------

Flujo

1. Se recomponen los componentes de la KEK mediante XOR  
2. Se valida la KEK utilizando KCV  
3. Se genera o importa una clave (PEK / BDK)  
4. Se utiliza DUKPT para derivar claves por transacción (bonus)

------------------------------------------------------------

# Preguntas Teoricas

1- ¿Podrían enviarse los dos componentes de la KEK por el mismo canal? ¿Qué problema habría?

Respuesta: No es recomendable enviar ambos componentes por el mismo canal. El propósito del split es el control dual: cada custodio mantiene una parte y ninguno por sí solo puede reconstruir la KEK. Si ambos componentes viajan por el mismo canal y ese canal es comprometido, un atacante obtiene la KEK completa y puede desencriptar cualquier key block protegido por ella. El split pierde su propósito y se convierte en una redundancia sin valor de seguridad.

2- ¿Qué método alternativo se te ocurre para que la contraparte te entregue la KEK sin que viaje entera por un solo medio?

Respuesta: Una alternativa es utilizar cifrado asimétrico: la contraparte cifra la KEK con la clave pública del receptor. De esta manera, la KEK no viaja en claro y solo el poseedor de la clave privada puede desencriptarla.

3- Si una de las dos partes que custodian sendos componentes de la KEK es comprometida, ¿queda comprometida la KEK? ¿Y si son las dos?

Respuesta: Si una sola parte es comprometida la KEK no queda expuesta, ya que la otra mitad sigue siendo secreta. Si ambas partes son comprometidas la KEK queda completamente expuesta y debe considerarse comprometida. En ese caso, todas las claves protegidas por esa KEK deben ser rotadas. El esquema de split key solo es seguro si al menos una de las partes permanece confidencial.

## 🛠️ Decisiones de Diseño y Criterio Técnico

Para la resolución de este desafío, se priorizó la **robustez, la legibilidad y el cumplimiento de estándares internacionales** sobre una implementación manual "desde cero".

### 1. Uso de Estándares (ANSI X9.143 y X9.24)
Se optó por utilizar la librería `psec` para el manejo de Key Blocks TR-31. En un entorno de seguridad profesional, la implementación manual de parseo de bloques es una fuente común de vulnerabilidades. Delegar esto a una librería probada garantiza la integridad de los datos.

### 2. Seguridad vs. Trazabilidad del Challenge
- **Visualización de llaves:** En una aplicación de producción real, las llaves (KEK, BDK, PEK) nunca se imprimirían en texto claro. Para fines de este desafío, se ha mantenido la salida por consola para facilitar la corrección, validación de resultados y trazabilidad del flujo por parte del revisor.
- **Manejo de Memoria:** Se asume que el entorno de ejecución es seguro para este ejercicio técnico. En producción, estas operaciones se realizarían idealmente dentro de un HSM o un enclave seguro.

### 3. Implementación del Bonus (DUKPT)
Se desarrolló la lógica de derivación de llaves (NRKGP) siguiendo estrictamente la especificación **ANSI X9.24-1**. La capacidad de orquestar diferentes primitivas criptográficas (AES, 3DES, CMAC) para lograr el descifrado DUKPT demuestra la comprensión del flujo de datos en transacciones financieras.

### 4. Metodología de Desarrollo
Este proyecto fue abordado con un enfoque de **Ingeniería Basada en Investigación**. Se utilizaron herramientas de IA y documentación técnica oficial para acelerar la curva de aprendizaje sobre protocolos criptográficos específicos, asegurando que la arquitectura final sea modular, testeable y profesional.