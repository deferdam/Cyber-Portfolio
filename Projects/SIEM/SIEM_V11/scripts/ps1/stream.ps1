$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Write-Host "[*] Streaming simulation (fake data). Start the app first, then refresh the UI."
& $Py "$Root\src\ingest\stream.py" $args
