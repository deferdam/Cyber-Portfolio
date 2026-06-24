$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"; $env:SIEM_MODE = "local"; $env:SIEM_HOST = "127.0.0.1"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Write-Host "[*] Mini SOAR | mode=LOCAL | http://127.0.0.1:5000 | browser opens itself. Ctrl+C to stop."
& $Py "$Root\src\server\app.py"
