# Verificar Python
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python no está instalado o no está en PATH" -ForegroundColor Red
    exit 1
}

Write-Host "Python encontrado:" 
python --version

# Crear entorno virtual si no existe
if (!(Test-Path ".\venv")) {
    Write-Host "Creando entorno virtual..."
    python -m venv venv
} else {
    Write-Host "Entorno virtual ya existe"
}

# Activar entorno
Write-Host "Activando entorno virtual..."
.\venv\Scripts\Activate.ps1

# Actualizar pip
Write-Host "Actualizando pip..."
python -m pip install --upgrade pip

# Instalar dependencias
Write-Host "Instalando dependencias..."
pip install -r requirements.txt

# Validación rápida
Write-Host "Validando instalación..."
python -c "import Crypto; import psec; print('Dependencias OK')"

Write-Host "Setup completado correctamente" -ForegroundColor Green