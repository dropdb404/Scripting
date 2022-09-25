# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Set_StoragePool.log -Append -Force -NoClobber

$PhysicalDisks = Get-PhysicalDisk -UniqueId "HPE 6.4TB Read Intensive-2 FHHL PCIe Workload Accelerator*" -CanPool $True
if ($PhysicalDisks.length -eq 2){
 New-StoragePool -FriendlyName "SQL_StoragePool" -StorageSubsystemFriendlyName "Storage Spaces*" -PhysicalDisks $PhysicalDisks | New-VirtualDisk -FriendlyName "SQL_VirtualDisk"-usemaximumsize -ProvisioningType fixed
}else{
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup("Number of FusionIO issue, will not create StoragePool",0,"Error",0x1)
}
Stop-Transcript