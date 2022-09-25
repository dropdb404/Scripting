# Disable Network SNP
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_SNP.log -Append -Force -NoClobber
Set-NetOffloadGlobalSetting -ReceiveSideScaling Disable -Chimney Disable | Out-Host
Get-NetOffloadGlobalSetting | Out-Host
Netsh int tcp set global netdma=disable | Out-Host
Netsh int tcp show global | Out-Host
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\parameters" -name "EnableTCPA" -value 0 -PropertyType "DWord"
Netsh int ipv4 set dynamicport tcp start=57535 num=8000 | Out-Host
Netsh int ipv4 set dynamicport udp start=57535 num=8000 | Out-Host
Netsh int ipv6 set dynamicport tcp start=57535 num=8000 | Out-Host
Netsh int ipv6 set dynamicport udp start=57535 num=8000 | Out-Host
Netsh int ipv4 show dynamicport tcp | Out-Host
Netsh int ipv4 show dynamicport udp | Out-Host
Netsh int ipv6 show dynamicport tcp | Out-Host
Netsh int ipv6 show dynamicport udp | Out-Host