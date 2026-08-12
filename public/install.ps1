$ErrorActionPreference = "Stop"
$MinNodeVersion = 18

function Write-Info($msg) { Write-Host ">>> $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host ">>> $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host ">>> $msg" -ForegroundColor Red; exit 1 }

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Warn "Node.js is not installed."
    Write-Host "  Install: winget install OpenJS.NodeJS.LTS"
    Write-Err "Please install Node.js and re-run."
}

$version = (node -v) -replace '^v', ''
$major = [int]($version.Split('.')[0])
if ($major -lt $MinNodeVersion) { Write-Err "Node.js v$major found, need >= v$MinNodeVersion." }
Write-Info "Node.js v$version detected"

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) { Write-Err "npm not found." }
Write-Info "npm v$(npm -v) detected"

$InstallDir = "$env:USERPROFILE\.gate\app"

# Install from GitHub
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    Write-Info "Installing Gate from GitHub..."
    if (Test-Path "$InstallDir\.git") {
        Write-Info "Existing installation found, updating..."
        Push-Location $InstallDir
        git pull --ff-only
        Pop-Location
    } else {
        if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
        git clone --depth 1 https://github.com/penumbraforge/gate.git $InstallDir
    }
    Push-Location $InstallDir
    Write-Info "Installing dependencies..."
    npm install
    Write-Info "Building..."
    npm run build
    Pop-Location
} else {
    Write-Info "git not found, installing via npm tarball..."
    npm install -g https://github.com/penumbraforge/gate/tarball/main
}

# Create wrapper script
$BinDir = "$env:USERPROFILE\.gate\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$nl = [Environment]::NewLine
$wrapper = "@echo off" + $nl + "node " + [char]34 + "%USERPROFILE%\.gate\app\bin\gate.js" + [char]34 + " %*"
Set-Content -Path "$BinDir\gate.cmd" -Value $wrapper
Write-Info "Installed to $BinDir\gate.cmd"

# Add to PATH for current session
$env:PATH = "$BinDir;$env:PATH"

# Persist to user PATH
$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable('PATH', "$BinDir;" + $userPath, 'User')
    Write-Info "Added $BinDir to user PATH"
}

# Run first-time setup
$gateJs = "$InstallDir\bin\gate.js"
if (Test-Path $gateJs) {
    Write-Info "Running first-time setup..."
    node $gateJs setup --skip-db
}

Write-Host ""
Write-Host "Gate installed successfully!" -ForegroundColor Green
Write-Host "  gate scan     Scan staged files"
Write-Host "  gate install  Install pre-commit hook"
Write-Host "  gate serve    Start the dashboard on :3000"
Write-Host ""
