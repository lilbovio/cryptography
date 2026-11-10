# Ejecuta la suite completa del proyecto y propaga el codigo de salida.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    python -m unittest discover -s tests -v
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host ""
        Write-Host "SUITE OK" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "SUITE CON FALLOS (codigo $code)" -ForegroundColor Red
    }
} finally {
    Pop-Location
}
exit $code
