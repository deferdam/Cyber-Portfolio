$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
Get-ChildItem "$Root\tests\test_*.py" | ForEach-Object {
  $out = & $Py $_.FullName 2>&1 | Select-String "passed|failed"
  Write-Host "[run] $($_.Name)  $out"
}
