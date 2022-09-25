# Disable USB no reboot
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\ModifyUsbstor_noreboot.log -Append -Force -NoClobber

"Change Usbstor registry key value" | Out-Host
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor" -Name Start -Value 4
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Usbstor"

$Path=$env:systemroot+"\inf"
$File="usbstor.inf","usbstor.pnf"
$FDate=Get-Date -format yyyyMMddhhmmss


$DAccess="D:AI(D;;FA;;;BA)(D;;FA;;;PU)(D;;FA;;;BU)(D;;FA;;;SY)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)"
Foreach($Fl in $File)
{
	Write-Output $Fl | Out-File $LogPath"\DA"$FDate".txt"
	Write-Output $DAccess | Out-File $LogPath"\DA"$FDate".txt" -Append
	Invoke-Command {icacls $Path /restore $LogPath"\DA"$FDate".txt" | Out-Host}
}
Stop-Transcript