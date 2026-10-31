param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\example_config.json",
    [string]$ModelPath = "",
    [string]$ListenHost = "",
    [int]$ListenPort = 53,
    [string]$Upstream = "",
    [switch]$Background
)

$python = (Get-Command python -ErrorAction Stop).Source
$cmd = "$python $PSScriptRoot\..\src\ai_firewall\guard.py --config `"$ConfigPath`""

if ($ModelPath) {
    $cmd += " --model `"$ModelPath`""
}
if ($ListenHost) {
    $cmd += " --listen-host `"$ListenHost`""
}
if ($ListenPort) {
    $cmd += " --listen-port $ListenPort"
}
if ($Upstream) {
    $cmd += " --upstream `"$Upstream`""
}

if ($Background) {
    Start-Process -FilePath $python -ArgumentList $cmd.Substring($python.Length + 1) -WindowStyle Hidden
} else {
    Invoke-Expression $cmd
}
