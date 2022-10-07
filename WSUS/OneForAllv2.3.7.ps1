$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
# LMA=List Missing All
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

            #Set-ItemProperty -Path 'HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -Value 'http://proxy.corp.com:8080/proxy.pac'
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
            & cmd /r 'schtasks /create /TN WSUSLOOP /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File c:\hotfix\checking\winupdate.ps1 -MaxUpdatesPerCycle 100" /SC onstart /RU SYSTEM /RL HIGHEST /F'
            & cmd /r 'shutdown /r /f /t 10 /d p:2:17 /c "Restart to make WSUS reg effective and start install updates"'
            write-output $env:COMPUTERNAME
        }
    } else {
            [void]$UnavaliableNode.Add($Server)
            write-host $now "Test-WSMAan failed on " $server.ComputerName $server.IP
    }
    write-host "====================================================================================="
    start-sleep 10
}

$UnavaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\UnvaliableNode.txt -encoding ASCII
$UnavaliableNode | format-table -AutoSize
$AvaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\AvaliableNode.txt -encoding ASCII
$AvaliableNode | format-table -AutoSize
if ($AvaliableNode.length -le 10) {start-sleep 120} else {start-sleep 10}


$start=Get-Date -format yyyyMMddHHmm
$end=(Date).AddDays(0).AddHours(9).AddMinutes(30)
write-host $start "Start to minitor WSUSLOOP status untill loop expired or WSUSLOOP completed (disabled)"
Write-Host "Loop start at $start, will force end at $end"
write-host `n
#for ($i=0; $i -lt 20; $i++) {

while ([DateTime]::Now -lt $end) {
#    ForEach ($Server in $List) {
    ForEach ($Server in $AvaliableNode) {
        write-host "==================Raw runtime logs as below:==============="          
        $password = convertto-securestring $server.Password -AsPlainText -Force
	    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
        $TempSession=New-PSSession -computername $server.IP -credential $cred

        $RebootCount=invoke-command -Session $TempSession -ArgumentList $start -scriptblock {
            param($start)
            $ErrorActionPreference = "SilentlyContinue"
            try {
                $countID1074=(Get-WinEvent -FilterHashtable @{logname='System'; id=1074; StartTime=$start}).count
            } catch {
                write-host "can not found WSUSLOOP reboot event, set RebootCount=0"
                $countID1074=0
            }
            $ErrorActionPreference = "Continue"
            # output the reboot count from remote session to local session variable $rebootCount
            $countID1074
         }
         write-host "Reboot counted:" $RebootCount
         write-host `n

        if ($RebootCount -lt $MaxReboot) {
            invoke-command -Session $TempSession -ArgumentList @($server.ComputerName,$server.IP) -scriptblock {
                Param($ComputerName,$IP)
                $now=Get-Date -format yyyyMMddHHmm
                If (Schtasks /query /TN "WSUSLOOP" | select-string "ready") {
                    write-host $now $ComputerName $IP "WSUSLOOP is idle, reboot to force start"
                    Shutdown /r /f /t 10 /d p:2:17 /c “WSUS reboot”
                    #$WSUSLOOP="Partial"
                } elseif (Schtasks /query /TN "WSUSLOOP" | select-string "running") {
                    write-host $now $ComputerName $IP "WSUSLOOP is running"
                    $WSUSLOOP=new-object pscustomobject –property @{status="Partial"}
                } elseif (Schtasks /query /TN "WSUSLOOP" | select-string "disable") {
                    write-host $now $ComputerName $IP "WSUSLOOP is completed"                    
                    # & cmd /r "C:\hotfix\checking\list_missing_hotfixes_all.bat"
                    $WSUSLOOP=new-object pscustomobject –property @{status="FULL"}
 	            }               
            }
        } elseif (($CurrentTry -ge $MaxTry) -and (!($Server.WSUSLOOP -eq "Partial"))) {
            invoke-command -Session $TempSession -ArgumentList @($server.ComputerName,$server.IP) -scriptblock {
                Param($ComputerName,$IP)
                $now=Get-Date -format yyyyMMddHHmm
                write-host $now $ComputerName $IP "WSUSLOOP MaxTry reached " $MaxTry ", stop and disable WSUSLOOP schedule task"
                & cmd /r 'schtasks /Change /TN "WSUSLOOP" /DISABLE'
                $WSUSLOOP=new-object pscustomobject –property @{status="Partial"}
            }
        } else {
            $now=Get-Date -format yyyyMMddHHmm
            write-host $now $ComputerName $IP "WSUSLOOP MaxTry had reached, no further action."
            $WSUSLOOP=new-object pscustomobject –property @{status="Partial"}
        }
        write-host `n
        write-host "======================WSUSLOOP Summary====================="
        $GetWSUSLOOP=invoke-command -Session $TempSession -scriptblock {$WSUSLOOP.status}
        if (!($GetWSUSLOOP -eq "")) {$Server.WSUSLOOP=$GetWSUSLOOP}
        write-host "Reboot counted for server "$server.ComputerName $server.IP ": " $RebootCount           
        write-host "Current checked status of WSUSLOOP: " $Server.WSUSLOOP
        write-host `n
        write-host "======================Remove PSSession====================="
        remove-pssession $TempSession
#        get-pssession | remove-pssession
       
        if ($AvaliableNode.length -le 10) {start-sleep 180} else {start-sleep 120}    
    }
}

$AvaliableNode | format-table -AutoSize | out-file -filepath $script:scriptRoot\AvaliableNode.txt -encoding ASCII -Append
$AvaliableNode | format-table -AutoSize

get-pssession | remove-pssession

ForEach ($Server in $AvaliableNode) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=Get-Date -format yyyyMMddHHmm
    write-host $now "Start to run list all missing updates and upload logs from" $server.ComputerName $server.IP
    invoke-command -computername $server.IP -credential $cred -ArgumentList @($SMBSVR,$SMBUSR,$SMBPWD,$server.ComputerName,$server.IP) -scriptblock {
        Param($SMBSVR,$SMBUSR,$SMBPWD,$CLIENT,$CLIENTIP)
        write-output "========================Runing List Missing All Schedule and upload logs======================="
        write-output ($CLIENT + " " + $CLIENTIP + " " + $env:COMPUTERNAME + " " + (Get-Date -format yyyyMMddHHmm))              
        If(!(test-path c:\hotfix\checking)) {New-Item -ItemType Directory -Force -Path c:\hotfix\checking}
        & cmd /r "c:\hotfix\checking\WSUSCOPY.BAT $SMBSVR $SMBUSR $SMBPWD"
        start-sleep 3
        
        $ErrorActionPreference = "SilentlyContinue"
        #Cleanup pervious push winupdate
        & cmd /r 'schtasks /Change /TN "WSUSLOOP" /DISABLE'
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "InstallWindowsUpdates"


        & cmd /r 'schtasks /create /TN ListMissingAll /TR "c:\hotfix\checking\list_missing_hotfixes_all.bat" /SC once /ST 00:00 /RU SYSTEM /RL HIGHEST /F'
        & cmd /r 'schtasks /run /TN ListMissingAll'
        start-sleep 180
        # while (get-process | select name | select-string mbsacli) {start-sleep 60}
        while (schtasks /query /TN ListMissingAll | Select-string "Running") {start-sleep 60}
        start-sleep 10        

        & cmd /r 'schtasks /create /TN ListMissing /TR "c:\hotfix\checking\list_missing_hotfixes.bat" /SC once /ST 00:00 /RU SYSTEM /RL HIGHEST /F'
        & cmd /r 'schtasks /run /TN ListMissing'
        start-sleep 180
        while (schtasks /query /TN ListMissing | Select-string "Running") {start-sleep 60}
        start-sleep 10      
        $ErrorActionPreference = "Continue"
        
        & cmd /r 'SCHTASKS /delete /TN ListMissingAll /F'
        & cmd /r 'SCHTASKS /delete /TN ListMissing /F'

        & cmd /r "c:\hotfix\checking\WSUSULOG.BAT $SMBSVR $SMBUSR $SMBPWD"
        start-sleep 3
        write-output "======================Completed List Missing All Schedule and upload logs====================="
    } -AsJob
    start-sleep 3
}

start-sleep 600

[integer]$GetJobCount=0
while((Get-Job -State Running).count){
    if ($getJobCount -gt 10){break} else {$GetJobCount++}
    Get-Job | ? {$_.State -eq 'Complete' -and $_.HasMoreData} | % {Receive-Job $_}
    Write-Host "Check and upload Jobs still running"
    start-sleep -seconds 180    
}

$results=Get-Job | Receive-Job
Write-Output $results
$results | out-file -filepath $script:ScriptLog -encoding ASCII -Append

#  Clean up jobs
get-job | Remove-Job -Force


ForEach ($Server in $AvaliableNode) {
	$password = convertto-securestring $server.Password -AsPlainText -Force
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Server.Username, $password
    $now=Get-Date -format yyyyMMddHHmm
    write-host $now "Start to grep list all missing updates summary from" $server.ComputerName $server.IP
    invoke-command -computername $server.IP -credential $cred -ArgumentList @($SMBSVR,$SMBUSR,$SMBPWD,$server.ComputerName,$server.IP) -scriptblock {
        Param($SMBSVR,$SMBUSR,$SMBPWD,$CLIENT,$CLIENTIP)

        $ErrorActionPreference = "SilentlyContinue"
        #Cleanup pervious push winupdate
        & cmd /r 'schtasks /Change /TN "WSUSLOOP" /DISABLE'
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "InstallWindowsUpdates"       
        $ErrorActionPreference = "Continue"

        $ListMissingAll=Get-ChildItem 'C:\hotfix\checking\missing_hotfix_info_all*.txt' | Sort {$_.LastWriteTime} | select -last 1
        $from=$ListMissingAll | select-string -pattern "Required hotfixes but missing " | Select-Object LineNumber
        $RequiredHotfix=Get-Content -Path $ListMissingAll | Select-Object -Index ($from.LineNumber..$listMissingAll.length)
        write-output "======================List missing all Summary====================="
        write-output ($CLIENT + " " + $CLIENTIP + " " + $env:COMPUTERNAME + " " + (Get-Date -format yyyyMMddHHmm))
        Write-Output $RequiredHotfix
        write-output "======================List missing all Summary====================="
    } -AsJob
    start-sleep 3
}

start-sleep 120

[integer]$GetJobCount=0
while((Get-Job -State Running).count){
    if ($getJobCount -gt 10){break} else {$GetJobCount++}
    Get-Job | ? {$_.State -eq 'Complete' -and $_.HasMoreData} | % {Receive-Job $_}
    Write-Host "List missing all Summary Jobs still running"
    start-sleep -seconds 180
}

$results=Get-Job | Receive-Job
Write-Output $results
$results | out-file -filepath $script:LMALog -encoding ASCII -Append

#  Clean up jobs
get-job | Remove-Job -Force

#winrm s winrm/config/client '@{TrustedHosts=""}'

Stop-Transcript
