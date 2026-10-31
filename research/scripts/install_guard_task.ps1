param(
    [string]$TaskName = "AI Firewall Guard",
    [string]$ConfigPath = "$PSScriptRoot\..\config\example_config.json",
    [string]$ModelPath = ""
)

$python = (Get-Command python -ErrorAction Stop).Source
$argList = "$PSScriptRoot\..\src\ai_firewall\guard.py --config `"$ConfigPath`""

if ($ModelPath) {
    $argList += " --model `"$ModelPath`""
}

$action = New-ScheduledTaskAction -Execute $python -Argument $argList
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest -Force
