Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Creating venv..."
python -m venv venv

Write-Host "Activating venv..."
& .\venv\Scripts\Activate.ps1

Write-Host "Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel --timeout 120 --retries 10

Write-Host "Installing requirements..."
python -m pip install -r requirements.txt --timeout 120 --retries 10 --prefer-binary

Write-Host "Done."
