$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
$script:LMALog = $MyInvocation.MyCommand.Path + ".LMA."+$now

$List=Import-CSV .\targetV2.csv
$WSUS=Get-Content .\3.WSUS.reg
$winupdate=Get-Content .\winupdate.ps1
$wsuscopy=Get-Content .\WSUSCOPY.BAT
$wsusulog=Get-Content .\WSUSULOG.BAT
$SMBSVR="\\10.194.117.115\WSUSULOG"
#$SMBSVR="\\10.194.108.254\WSUSULOG"
#$SMBSVR="\\192.168.3.86\WSUSULOG"
$SMBUSR=$env:computername+"\wsuslog"
$SMBPWD="Log2WSUSWINDM"
$AvaliableNode = New-Object -TypeName System.Collections.ArrayList
$UnavaliableNode = New-Object -TypeName System.Collections.ArrayList
[integer]$MaxReboot=10

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber
winrm s winrm/config/client '@{TrustedHosts="*"}'



ForEach ($Server in $List) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=Get-Date -format yyyyMMddHHmm
    if (Test-WSMan -ComputerName $server.IP -credential $cred -Authentication Default) {
        $Server.hostname=invoke-command -computername $server.IP -credential $cred -scriptblock {$env:COMPUTERNAME}
        [void]$AvaliableNode.Add($Server)
        write-host $now "Import wsus reg file to remote computer" $server.ComputerName $server.IP "and reboot to run WSUSLOOP"
        invoke-command -computername $server.IP -credential $cred -ArgumentList @($WSUS,$winupdate,$wsuscopy,$wsusulog) -scriptblock {
            Param($WSUS,$winupdate,$wsuscopy,$wsusulog)
            If(!(test-path c:\hotfix\checking)) {New-Item -ItemType Directory -Force -Path c:\hotfix\checking}
            $WSUS | out-file -filepath c:\hotfix\checking\wsus.reg -encoding ASCII
            $winupdate | out-file -filepath c:\hotfix\checking\winupdate.ps1 -encoding ASCII
            $wsuscopy | out-file -filepath c:\hotfix\checking\WSUSCOPY.BAT -encoding ASCII
            $wsusulog | out-file -filepath c:\hotfix\checking\WSUSULOG.BAT -encoding ASCII

            #Set-ItemProperty -Path 'HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -Value 'http://proxy.corp.hkjc.com:8080/proxy.pac'
            if ((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").AutoConfigURL) {
                Remove-ItemProperty -Path 'HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL
            }
            
            if ((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").proxyenable -eq 1) {
                $ProxyOverride=((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").proxyoverride)
                if (!($ProxyOverride | Select-String "10.194.117.115")) {
                    $new+="10.194.117.115;" + $ProxyOverride
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value $new
                }
            }

            # & cmd /r "c:\hotfix\checking\WSUSCOPY.BAT $SMBSVR $SMBUSR $SMBPWD"
            & cmd /r "regedit.exe /s c:\hotfix\checking\wsus.reg"
            & cmd /r "c:\windows\system32\powercfg.exe -change -monitor-timeout-ac 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -monitor-timeout-dc 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -disk-timeout-ac 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -disk-timeout-dc 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -standby-timeout-ac 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -standby-timeout-dc 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -hibernate-timeout-ac 0"
            & cmd /r "c:\windows\system32\powercfg.exe -change -hibernate-timeout-dc 0" 
            #$StartUp=$env:appdata + "\Microsoft\Windows\Start Menu\Programs\Startup\WinUpdate.bat"
            #"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File c:\hotfix\checking\winupdate.ps1 -MaxUpdatesPerCycle 100" | out-file -filepath $StartUp -encoding ASCII
            #& cmd /r 'schtasks /create /TN WSUSLOOP /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File c:\hotfix\checking\winupdate.ps1 -MaxUpdatesPerCycle 100" /SC onstart /RU SYSTEM /RL HIGHEST /F'
            #& cmd /r 'shutdown /r /f /t 10 /d p:2:17 /c "Restart to make WSUS reg effective and start install updates"'
            write-output $env:COMPUTERNAME
        }
    } else {
            [void]$UnavaliableNode.Add($Server)
            write-host $now "Test-WSMAan failed on " $server.ComputerName $server.IP
    }
    write-host "====================================================================================="
    start-sleep 3
}


$UnavaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\UnvaliableNode.txt -encoding ASCII
$UnavaliableNode | format-table -AutoSize
$AvaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\AvaliableNode.txt -encoding ASCII
$AvaliableNode | format-table -AutoSize
#if ($AvaliableNode.length -le 10) {start-sleep 120} else {start-sleep 10}
start-sleep 3

get-pssession | remove-pssession

ForEach ($Server in $AvaliableNode) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=get-date -format yyyyMMddHHmm
    write-host $now "Start to upload logs from" $server.ComputerName $server.IP
    invoke-command -computername $server.IP -credential $cred -ArgumentList @($SMBSVR,$SMBUSR,$SMBPWD,$server.ComputerName,$server.IP) -scriptblock {
        Param($SMBSVR,$SMBUSR,$SMBPWD,$CLIENT,$CLIENTIP)
        write-output "==========================Uploading logs========================"
        write-output ($CLIENT + " " + $CLIENTIP + " " + $env:COMPUTERNAME + " " + (get-date -format yyyyMMddHHmm))
        & cmd /r "c:\hotfix\checking\WSUSULOG.BAT $SMBSVR $SMBUSR $SMBPWD"
        start-sleep 3
        write-output "======================Completed upload logs====================="
    } -AsJob
    start-sleep 3
}

start-sleep 180

while((Get-Job -State Running).count){
    Get-Job | ? {$_.State -eq 'Complete' -and $_.HasMoreData} | % {Receive-Job $_}
    Write-Host "Check and upload Jobs still running"
    start-sleep -seconds 180
}

$results=Get-Job | Receive-Job
Write-Output $results
$results | out-file -filepath $script:ScriptLog -encoding ASCII -Append

#  Clean up jobs
get-job | Remove-Job

ForEach ($Server in $AvaliableNode) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=get-date -format yyyyMMddHHmm
    write-host $now "Start to grep list all missing updates summary from" $server.ComputerName $server.IP
    invoke-command -computername $server.IP -credential $cred -ArgumentList @($SMBSVR,$SMBUSR,$SMBPWD,$server.ComputerName,$server.IP) -scriptblock {
        Param($SMBSVR,$SMBUSR,$SMBPWD,$CLIENT,$CLIENTIP)       
        $ListMissingAll=Get-ChildItem 'C:\hotfix\checking\missing_hotfix_info_all*.txt' | Sort {$_.LastWriteTime} | select -last 1
        $from=$ListMissingAll | select-string -pattern "Required hotfixes but missing " | Select-Object LineNumber
        $RequiredHotfix=Get-Content -Path $ListMissingAll | Select-Object -Index ($from.LineNumber..$listMissingAll.length)
        write-output "======================List missing all Summary====================="
        write-output ($CLIENT + " " + $CLIENTIP + " " + $env:COMPUTERNAME + " " + (get-date -format yyyyMMddHHmm))
        Write-Output $RequiredHotfix
        write-output "======================List missing all Summary====================="
    } -AsJob
    start-sleep 3
}

start-sleep 120

while((Get-Job -State Running).count){
    Get-Job | ? {$_.State -eq 'Complete' -and $_.HasMoreData} | % {Receive-Job $_}
    Write-Host "List missing all Summary Jobs still running"
    start-sleep -seconds 180
}

$results=Get-Job | Receive-Job
Write-Output $results
$results | out-file -filepath $script:LMALog -encoding ASCII -Append

#  Clean up jobs
get-job | Remove-Job


#winrm s winrm/config/client '@{TrustedHosts=""}'

Stop-Transcript
