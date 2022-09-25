# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_NETBIOS.log -Append -Force -NoClobber

$adapters= (Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.Description -like "Microsoft Network Adapter Multiplexor Driver*" })
foreach ($adapter in $adapters){
Write-Host `"$($adapter.PSComputerName)`" `"$($adapter.Description)`" `"$($adapter.IPAddress)`" " - CURRENT Setting $($adapter.TcpipNetbiosOptions)"`r
}
Write-Host `r
foreach ($adapter in $adapters){
$adapter.settcpipnetbios(2)
}
Write-Host `r
$adapters= (Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.Description -like "Microsoft Network Adapter Multiplexor Driver*" })
foreach ($adapter in $adapters){
Write-Host `"$($adapter.PSComputerName)`" `"$($adapter.Description)`" `"$($adapter.IPAddress)`" " - NEW Setting $($adapter.TcpipNetbiosOptions)"`r
}
Stop-Transcript