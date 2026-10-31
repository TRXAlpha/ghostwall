param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\example_config.json",
    [string]$OutPath = "endpoint_snapshot.json",
    [string]$BaselinePath = "",
    [int]$SinceHours = 24,
    [string]$MinSeverity = "high"
)

.\scripts\collect_endpoint.ps1 -OutPath $OutPath -SinceHours $SinceHours

$cmd = "python $PSScriptRoot\..\src\ai_firewall\enforce_endpoint.py --config `"$ConfigPath`" --snapshot `"$OutPath`" --min-severity $MinSeverity"
if ($BaselinePath) {
    $cmd += " --baseline `"$BaselinePath`""
}

Invoke-Expression $cmd
