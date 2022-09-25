# Enable remote powershell and allow RemotePS to passthru firewall
    # reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    # Set-Item WSMan:\localhost\Client\TrustedHosts *
    # winrm set winrm/config/client '@{TrustedHosts="*"}'

$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\EnableRemotePS.log -Append -Force -NoClobber

if ($psversiontable.psversion.major -le 2){

    #Skip network location setting if local machine is joined to a domain. 
    if (1,3,4,5 -notcontains (Get-WmiObject win32_computersystem).DomainRole) {
    
        #Set network location setting only for win vista and later on operating systems 
        if([environment]::OSVersion.version.Major -ge 6) {

            #Get network connections 
            $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")) 
            $connections = $networkListManager.GetNetworkConnections() 

            #Set network location to Private for all networks 
            $connections | % {$_.GetNetwork().SetCategory(1)}
        }
    }
    netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes
    netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new remoteip=any
    netsh advfirewall firewall set rule name="Windows Remote Management - Compatibility Mode (HTTP-In)" new remoteip=any
    Enable-PSRemoting -Force

} elseif ($psversiontable.psversion.major -gt 2){
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
}

Stop-Transcript