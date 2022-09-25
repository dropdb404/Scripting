#DisableDomainCreds0
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\DisableDomainCreds0.log -Append -Force -NoClobber

Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds -Value 0 -PropertyType DWord
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Stop-Transcript
