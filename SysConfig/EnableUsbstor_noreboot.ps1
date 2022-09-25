# Enable USB no reboot
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\EnableUsbstor_noreboot.log -Append -Force -NoClobber

"Change Usbstor registry key value" | Out-Host
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor" -Name Start -Value 4
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor"

$Path=$env:systemroot+"\inf"
$File="usbstor.inf","usbstor.pnf"
$FDate=Get-Date -format yyyyMMddhhmmss

$EAccess="D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)"
Foreach($Fl in $File)
{
	Write-Output $Fl | Out-File $LogPath"\EA"$FDate".txt"
	Write-Output $EAccess | Out-File $LogPath"\EA"$FDate".txt" -Append
	Invoke-Command {Takeown /A /F $Path"\"$Fl | Out-Host}
	Invoke-Command {icacls $Path /restore $LogPath"\EA"$FDate".txt" | Out-Host}
	Invoke-Command {icacls $Path"\"$Fl /setowner SYSTEM | Out-Host}
}
Stop-Transcript