# Disable NIC Large Send Offload
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_LSO.log -Append -Force -NoClobber
Get-NetAdapterLSO | Out-Host
Get-NetAdapterLSO | where-object {$_.IPv6Enabled -match $True} | foreach-object {Set-NetAdapterLSO -Name $_.Name -IPv6Enabled $False} | Out-Host
Get-NetAdapterLSO | where-object {$_.IPv4Enabled -match $True} | foreach-object {Set-NetAdapterLSO -Name $_.Name -IPv4Enabled $False} | Out-Host
Get-NetAdapterLSO | where-object {$_.V1IPv4Enabled -match $True} | foreach-object {Set-NetAdapterLSO -Name $_.Name -V1IPv4Enabled $False} | Out-Host
Get-NetAdapterLSO | Out-Host
Stop-Transcript