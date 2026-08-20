$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"; $env:SIEM_MODE = "server"; $env:SIEM_HOST = "127.0.0.1"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Write-Host "[*] Mini SOAR | mode=SERVER (v10 skeleton, loopback only, no auth yet) | http://127.0.0.1:5000. Ctrl+C to stop."
& $Py "$Root\src\server\app.py"
