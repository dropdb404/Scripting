#Disable AutoRun
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_autorun.log -Append -Force -NoClobber

"Disable AutoRun" | Out-Host
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name NoDriveTypeAutoRun -Value 0xff -PropertyType DWord
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"

Stop-Transcript
