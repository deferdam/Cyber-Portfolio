# run_server.ps1 - Mini SOAR Web Server
$env:PYTHONPATH = "$PSScriptRoot\src"
$PyExe = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Write-Host "[*] Starting Mini SOAR at http://localhost:5000"
Write-Host "[*] Press Ctrl+C to stop."
& $PyExe "$PSScriptRoot\src\server\app.py"
