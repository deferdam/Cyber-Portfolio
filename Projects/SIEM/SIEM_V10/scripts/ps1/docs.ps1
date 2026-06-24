$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
Write-Host "[*] Opening documentation..."
Start-Process "$Root\docs\index.html"
