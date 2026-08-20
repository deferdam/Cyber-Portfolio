$Root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$env:PYTHONPATH = "$Root\src"
$Py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
$In = if ($args.Count -ge 1) { $args[0] } else { "$Root\samples\demo_linux_attack.jsonl" }
$Out = if ($args.Count -ge 2) { $args[1] } else { "$Root\out\large" }
$Fmt = if ($args.Count -ge 3) { $args[2] } else { "auto" }
Write-Host "[*] Pipeline | input=$In | out=$Out | format=$Fmt"
Remove-Item "$Out\tickets.jsonl" -ErrorAction SilentlyContinue
& $Py -m ingest.replay --input "$In" --out-dir "$Out" --format "$Fmt"
