
#$LogPath = "C:\Temp"
$LogPath = "Y:\SP3D"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}

$logFile=$LogPath+"\"+$env:COMPUTERNAME+"_SP3D_NET_TEST.log"
$LogfileSysout=$LogPath+"\"+$env:COMPUTERNAME+"_SP3D_NET_TEST_sysout.log"

function PINGtracert {

Get-NetAdapterHardwareInfo | Sort-Object Slot,Function | FT -AutoSize

Get-NetLbfoTeam | FT -AutoSize

if ($env:COMPUTERNAME -like 'WINDB*ST*') {

Write-Output "Ping and tracert Data network ST gateway and route to HV"
ping 10.8.31.254
tracert -d 10.8.31.254

Write-Output "Ping and tracert Replication network ST gateway and route to HV"
ping 10.8.42.254
tracert -d 10.8.42.254
ping 10.8.74.254
tracert -d 10.8.74.254

Write-Output "Ping and tracert Backup network ST gateway and route to HV"
ping 10.8.43.254
tracert -d 10.8.43.254
ping 10.8.75.254
tracert -d 10.8.75.254

Write-Output "Ping and tracert MGMT network ST gateway"
ping 10.8.39.254
tracert -d 10.8.39.254

} elseif ($env:COMPUTERNAME -like 'WINDB*HV*') {

Write-Output "Ping and tracert Data network HV gateway and route to ST"
ping 10.8.31.254
tracert -d 10.8.31.254

Write-Output "Ping and tracert Replication network HV gateway and route to ST"
ping 10.8.74.254
tracert -d 10.8.74.254
ping 10.8.42.254
tracert -d 10.8.42.254

Write-Output "Ping and tracert Backup network HV gateway and route to ST"
ping 10.8.75.254
tracert -d 10.8.75.254
ping 10.8.43.254
tracert -d 10.8.43.254

Write-Output "Ping and tracert MGMT network HV gateway"
ping 10.8.73.254
tracert -d 10.8.73.254


} else {

$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup("Server environment discrepency, please check if this server is WIN_DM SQL AAG server with 4 NIC teaming",0,"Error",0x1)

}

}

Start-Transcript -Path $Logfile -Append -Force -NoClobber


#Before test reference

Write-Output ("Check Teaming NIC members, Ping and tracert -d before test on $env:COMPUTERNAME at " + (get-Date -f yyyyMMddHHmm))

PINGtracert | Out-File -FilePath $LogfileSysout -Encoding ascii -Append

# Disable 1st NIC member of each NIC teams, test and resume

Write-Output ("Ping and tracert after disalbe 1st NIC team members on $env:COMPUTERNAME at " + (get-Date -f yyyyMMddHHmm))

Get-NetLbfoTeam | foreach {
Write-Output Disabling $_.Members[0]
Disable-NetAdapter -name $_.Members[0] -confirm:$false
start-sleep 10
}

PINGtracert | Out-File -FilePath $LogfileSysout -Encoding ascii -Append

Get-NetLbfoTeam | foreach {
Write-Output enabling $_.Members[0]
enable-NetAdapter -name $_.Members[0]
start-sleep 10
}


# Disable 2nd NIC member of each NIC teams, test and resume

Write-Output ("Ping and tracert after disalbe 2nd NIC team members on $env:COMPUTERNAME at " + (get-Date -f yyyyMMddHHmm))

Get-NetLbfoTeam | foreach {
Write-Output Disabling $_.Members[1]
Disable-NetAdapter -name $_.Members[1] -confirm:$false
start-sleep 10
}

PINGtracert | Out-File -FilePath $LogfileSysout -Encoding ascii -Append

Get-NetLbfoTeam | foreach {
Write-Output enabling $_.Members[1]
enable-NetAdapter -name $_.Members[1]
start-sleep 10
}


#After test for cross check

Write-Output ("Check Teaming NIC members, Ping and tracert after test on $env:COMPUTERNAME at " + (get-Date -f yyyyMMddHHmm))

PINGtracert | Out-File -FilePath $LogfileSysout -Encoding ascii -Append


Stop-Transcript