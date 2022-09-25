$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now

$List=Import-CSV .\targetV2.csv
$AvaliableNode = New-Object -TypeName System.Collections.ArrayList
$UnavaliableNode = New-Object -TypeName System.Collections.ArrayList

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber
winrm s winrm/config/client '@{TrustedHosts="*"}'

ForEach ($Server in $List) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=Get-Date -format s
    if (Test-WSMan -ComputerName $server.IP -credential $cred -Authentication Default) {
        $TempSession=New-PSSession -computername $server.IP -credential $cred
        $Server.hostname=invoke-command -Session $TempSession -scriptblock {$env:COMPUTERNAME}            
        write-host $now "Checking target computer" $server.ComputerName $server.IP $Server.hostname "for logged in user sessions"
        invoke-command $TempSession -scriptblock {
            $ErrorActionPreference = "Continue"
            $QUResult = quser 2>&1
            if($QUResult -notmatch "no user exists for"){         
                Write-Host "User Sessions found in : " $env:computername -ForegroundColor Red
                $QUResult
                $UserLoggedIn=new-object pscustomobject –property @{UserCount=$QUResult.count}
            } else {
                write-host "No User Logged In : " $env:computername -ForegroundColor Green
                $UserLoggedIn=new-object pscustomobject –property @{UserCount="0"}
            }
        }
        $Server.UserLoggedIn=invoke-command $TempSession -scriptblock {$UserLoggedIn.UserCount}
        [void]$AvaliableNode.Add($Server)
    } else {
        [void]$UnavaliableNode.Add($Server)
        write-host $now "Test-WSMAan failed on " $server.ComputerName $server.IP
    }
    remove-pssession $TempSession
    write-host "====================================================================================="
    start-sleep 3
}

$UnavaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\UnvaliableNode.txt -encoding ASCII
$UnavaliableNode | format-table -AutoSize
$AvaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\AvaliableNode.txt -encoding ASCII
$AvaliableNode | format-table -AutoSize

get-pssession | remove-pssession

#winrm s winrm/config/client '@{TrustedHosts=""}'

Stop-Transcript
