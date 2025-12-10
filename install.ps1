# install.ps1
$ErrorActionPreference = "Stop"

$AppName   = "quantum-auth-client"
$ExeName   = "quantum-auth-client.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "QuantumAuthClient"
$ProtocolKey = "HKCU:\Software\Classes\qa"

Write-Host "[QuantumAuth] Installing..."

# 1) Ensure binary next to script
if (-not (Test-Path -Path ".\$ExeName")) {
    Write-Error "Binary .\$ExeName not found next to install.ps1"
    exit 1
}

# 2) Create install dir and copy binary
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item ".\$ExeName" (Join-Path $InstallDir $ExeName) -Force

Write-Host "[QuantumAuth] Binary installed to $InstallDir\$ExeName"

# 3) Register qa:// URL protocol (per user)
New-Item -Path $ProtocolKey -Force | Out-Null
New-ItemProperty -Path $ProtocolKey -Name "URL Protocol" -Value "" -PropertyType String -Force | Out-Null

$commandKey = Join-Path $ProtocolKey "shell\open\command"
New-Item -Path $commandKey -Force | Out-Null

$commandValue = "`"$InstallDir\$ExeName`" `"%1`""
Set-ItemProperty -Path $commandKey -Name "(default)" -Value $commandValue

Write-Host "[QuantumAuth] Registered qa:// URL protocol"

# 4) (Optional) Hint about PATH
if ($env:PATH -notlike "*$InstallDir*") {
    Write-Host ""
    Write-Host "[QuantumAuth] Note: $InstallDir is not in your PATH."
    Write-Host "You can run the client from Start → Run:"
    Write-Host "  `"$InstallDir\$ExeName`""
}

Write-Host ""
Write-Host "[QuantumAuth] Install complete."
Write-Host "Try this in a browser or Win+R: qa://test"
