$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"; $env:SIEM_MODE = "showcase"; $env:SIEM_HOST = "127.0.0.1"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Write-Host "[*] Mini SOAR | mode=SHOWCASE (sealed demo, fake data) | http://127.0.0.1:5000. Ctrl+C to stop."
& $Py "$Root\src\server\app.py"
