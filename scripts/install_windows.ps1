# AuditForwarder - PowerShell installer for Windows
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File install_windows.ps1

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\AuditForwarder",
    [string]$ConfigDir  = "C:\ProgramData\AuditForwarder",
    [string]$DataDir    = "C:\ProgramData\AuditForwarder\data",
    [string]$LogDir     = "C:\ProgramData\AuditForwarder\log",
    [string]$SourceDir  = "$PSScriptRoot\..\build\Release",
    [switch]$Start,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "AuditForwarder"
$ExeName     = "auditforwarderd.exe"

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Stop-Service {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "[stop] stopping service $ServiceName..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
}

function Remove-Service {
    Stop-Service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "[uninstall] removing service..."
        sc.exe delete $ServiceName | Out-Null
    }
}

function Install-Binary {
    $src = Join-Path $SourceDir $ExeName
    if (-not (Test-Path $src)) { throw "Binary not found: $src" }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $src "$InstallDir\$ExeName" -Force
}

function Install-Config {
    New-Item -ItemType Directory -Force -Path $ConfigDir, $ConfigDir\keys, $ConfigDir\tls, $DataDir\batches, $LogDir | Out-Null
    $cfgSrc = Join-Path $PSScriptRoot "..\config\agent.yaml"
    $rulesSrc = Join-Path $PSScriptRoot "..\config\rules.yaml"
    if (-not (Test-Path "$ConfigDir\agent.yaml")) { Copy-Item $cfgSrc $ConfigDir\agent.yaml }
    if (-not (Test-Path "$ConfigDir\rules.yaml")) { Copy-Item $rulesSrc $ConfigDir\rules.yaml }
}

function Generate-Keys {
    $keyPath = "$ConfigDir\keys\agent.pem"
    if (-not (Test-Path $keyPath)) {
        Write-Host "[keys] generating Ed25519 signing key..."
        New-Item -ItemType Directory -Force -Path (Split-Path $keyPath) | Out-Null
        openssl genpkey -algorithm ed25519 -out $keyPath 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[keys] openssl not found; using HMAC fallback"
        } else {
            openssl pkey -in $keyPath -pubout -out "$ConfigDir\keys\agent.pub"
        }
    }
}

function New-Service {
    $binPath = "`"$InstallDir\$ExeName`" -c `"$ConfigDir\agent.yaml`" -d $DataDir"
    New-Service -Name $ServiceName -BinaryPathName $binPath `
        -DisplayName "AuditForwarder Security Audit Agent" `
        -Description "Enterprise cross-platform security audit agent." `
        -StartupType Automatic | Out-Null
    Write-Host "[service] created: $ServiceName"
}

function Start-IfRequested {
    if ($Start) {
        Start-Service -Name $ServiceName
        Write-Host "[service] started: $ServiceName"
    }
}

# ---------------------------------------------------------------------------

if ($Uninstall) {
    Require-Admin
    Remove-Service
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "AuditForwarder uninstalled.  Data left in $ConfigDir."
    exit 0
}

Require-Admin
Install-Binary
Install-Config
Generate-Keys
Stop-Service
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    sc.exe delete $ServiceName | Out-Null
}
New-Service
Start-IfRequested

Write-Host ""
Write-Host "AuditForwarder installed successfully."
Write-Host "  Binary:  $InstallDir\$ExeName"
Write-Host "  Config:  $ConfigDir\agent.yaml"
Write-Host "  Rules:   $ConfigDir\rules.yaml"
Write-Host "  Data:    $DataDir"
Write-Host "  Logs:    $LogDir"
Write-Host ""
Write-Host "  Manage with:  Get-Service AuditForwarder"
Write-Host "  View logs:    Get-EventLog -LogName Application -Source AuditForwarder -Newest 50"
