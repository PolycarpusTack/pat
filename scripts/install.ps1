# Pat Fortress - Windows PowerShell Installation Script
# Downloads and installs the latest version of Pat Fortress on Windows

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:USERPROFILE\bin",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Configuration
$REPO = "pat-fortress/pat-fortress"
$BINARY_NAME = "pat-fortress.exe"

function Write-Banner {
    Write-Host "🏰 Pat Fortress Windows Installer" -ForegroundColor Blue
    Write-Host "=================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Show-Help {
    Write-Host "Pat Fortress Windows Installer"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version <version>     Install specific version (default: latest)"
    Write-Host "  -InstallDir <path>     Installation directory (default: $env:USERPROFILE\bin)"
    Write-Host "  -Help                  Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install.ps1                    # Install latest version"
    Write-Host "  .\install.ps1 -Version 2.0.0    # Install specific version"
    Write-Host ""
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod "https://api.github.com/repos/$REPO/releases/latest"
        return $response.tag_name.TrimStart('v')
    }
    catch {
        Write-Error "Failed to get latest version: $_"
        exit 1
    }
}

function Download-Binary {
    param(
        [string]$Version,
        [string]$Architecture
    )

    $binaryName = "pat-fortress_${Version}_windows_${Architecture}.exe"
    $downloadUrl = "https://github.com/$REPO/releases/download/v$Version/$binaryName"
    $tempFile = Join-Path $env:TEMP $binaryName

    Write-Info "Downloading $binaryName..."

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        return $tempFile
    }
    catch {
        Write-Error "Failed to download binary: $_"
        exit 1
    }
}

function Install-Binary {
    param(
        [string]$TempFile,
        [string]$InstallDirectory
    )

    $installPath = Join-Path $InstallDirectory $BINARY_NAME

    # Create install directory if it doesn't exist
    if (-not (Test-Path $InstallDirectory)) {
        Write-Info "Creating installation directory: $InstallDirectory"
        New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    }

    Write-Info "Installing to $installPath..."
    Copy-Item $TempFile $installPath -Force

    # Cleanup
    Remove-Item $TempFile -Force

    return $installPath
}

function Add-ToPath {
    param([string]$Directory)

    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -notlike "*$Directory*") {
        Write-Info "Adding $Directory to PATH..."
        $newPath = "$currentPath;$Directory"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Info "✅ Added to PATH (restart terminal to take effect)"
    } else {
        Write-Info "Directory already in PATH"
    }
}

function Test-Installation {
    param([string]$InstallPath)

    if (Test-Path $InstallPath) {
        Write-Info "✅ Pat Fortress installed successfully!"
        Write-Host ""
        Write-Host "🚀 Quick Start:" -ForegroundColor Cyan
        Write-Host "   pat-fortress                    # Start Pat Fortress"
        Write-Host "   start http://localhost:8025     # Open web interface"
        Write-Host ""
        Write-Host "📧 Configure your app to send emails to localhost:1025" -ForegroundColor Yellow
        Write-Host "📋 Full documentation: https://github.com/$REPO" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "💡 Note: Restart your terminal to use 'pat-fortress' command" -ForegroundColor Yellow
    } else {
        Write-Error "Installation verification failed"
        exit 1
    }
}

function Main {
    Write-Banner

    if ($Help) {
        Show-Help
        return
    }

    Write-Info "Detecting architecture..."
    $architecture = Get-Architecture
    Write-Info "Architecture: $architecture"

    if ($Version -eq "latest") {
        Write-Info "Getting latest version..."
        $Version = Get-LatestVersion
    }
    Write-Info "Version: $Version"

    Write-Info "Downloading binary..."
    $tempFile = Download-Binary -Version $Version -Architecture $architecture

    Write-Info "Installing binary..."
    $installPath = Install-Binary -TempFile $tempFile -InstallDirectory $InstallDir

    Write-Info "Updating PATH..."
    Add-ToPath -Directory $InstallDir

    Write-Info "Verifying installation..."
    Test-Installation -InstallPath $installPath

    Write-Host ""
    Write-Info "🎉 Installation complete!"
}

# Run main function
Main