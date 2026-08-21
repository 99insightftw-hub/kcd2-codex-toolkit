$ErrorActionPreference = "Stop"

$pluginRoot = Split-Path -Parent $PSScriptRoot
$bundledRuntime = Join-Path $pluginRoot "runtime"
if (Test-Path -LiteralPath (Join-Path $bundledRuntime "src") -PathType Container) {
    $repositoryRoot = $bundledRuntime
    $runner = Join-Path $bundledRuntime "scripts\run_kcd2_native_probes_mcp.py"
}
else {
    $repositoryRoot = (Resolve-Path (Join-Path $pluginRoot "..\..")).Path
    $runner = Join-Path $repositoryRoot "scripts\run_kcd2_native_probes_mcp.py"
}
$env:PYTHONPATH = Join-Path $repositoryRoot "src"
$env:PYTHONDONTWRITEBYTECODE = '1'

& python.exe -B $runner --repository-root $repositoryRoot
exit $LASTEXITCODE
