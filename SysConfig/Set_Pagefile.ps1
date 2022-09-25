# Set Pagefile size
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\SetPagefile.log -Append -Force -NoClobber
$Pagepath="D:\pagefile.sys"
$Computer=gwmi -Class Win32_ComputerSystem
$PMem=[BigInt] $Computer.TotalPhysicalMemory/1024/1024
$PageSize=$PMem+1024
$PageDrive=gwmi win32_logicaldisk | Where-Object {$_.DeviceID -match "D:"}
$PageFree=[BigInt] $PageDrive.FreeSpace/1024/1024
If($PageFree -lt ([BigInt] $PageSize*1.1))
{
	"Insufficient disk space for create pagefile, current D drive free space "+([BigInt] $PageFree/1024)+" GB" | Out-Host
}
Else
{
	$Computer.AutomaticManagedPagefile=$False
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\" -name "pagingfiles" -type multistring -value "$Pagepath $PageSize $PageSize"
	"Pagefile was set to D drive with "+([BigInt] $PageSize/1024)+" GB" | Out-Host
}
Stop-Transcript
