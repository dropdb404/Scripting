#Test-wsman -computername YourTargetServer -authentication default 

function LogWrite {
   Param ([string]$logstring)
   $now = Get-Date -format s
#   Add-Content $Logfile -value "$now $logstring"
   Add-Content $Logfile -value "$logstring"
   Write-Host $now $logstring
}

$script:ScriptPathFullSuccess = $MyInvocation.MyCommand.Path + "_success.log"
$script:ScriptPathFullFail = $MyInvocation.MyCommand.Path + "_fail.log"
$script:ScriptPathFull = $MyInvocation.MyCommand.Path + ".log"
$script:ScriptPathPrefix = split-path $MyInvocation.MyCommand.Path
Start-Transcript -Path $script:ScriptPathFull -Append -Force -NoClobber

winrm set winrm/config/client '@{TrustedHosts="*"}'
$List = Import-CSV $script:ScriptPathPrefix\targetv2.csv

ForEach ($Server in $List)
{
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $message = $Server.ComputerName + "," +$Server.IP + "," + $Server.Username + "," + $Server.Password
    $ErrorActionPreference = "SilentlyContinue"
    if (Test-wsman -computername $server.IP -Credential $cred -authentication default) { 
    $Logfile=$script:ScriptPathFullSuccess
    write-host "Test Remote Powershell Success"
    LogWrite $message
    } else {
    $Logfile=$script:ScriptPathFullFail
    write-host "Test Remote Powershell failed, please check username,password, firewall, network connection"
    LogWrite $message
    }
    $ErrorActionPreference = "Continue"	
}

#winrm set winrm/config/client '@{TrustedHosts=""}'
Stop-Transcript
