# Thai Injection Eval CLI launcher for Windows PowerShell
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}
& $python -m core.cli @args
