# Install .Net Framework 3.5 Feature
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Install_NetFramework35.log -Append -Force -NoClobber
$CDDrive=GWMI Win32_CDROMDrive
$DVDRom=$CDDrive.Drive
Install-WindowsFeature Net-Framework-Features -Source "$DVDRom\Sources\SXS"
Get-WindowsFeature | Where-Object {$_.Installed -match "True"} | Where-Object {$_.Name -match "Net-Framework-Features"}
Stop-Transcript