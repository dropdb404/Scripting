####################### WINRM Server side setup #########################

## Assume your Windows >= 2012 and PowerShell >= 4.0, otherwise it won't work. 

#Client Authentication (1.3.6.1.5.5.7.3.2) 
#Server Authentication (1.3.6.1.5.5.7.3.1)
#email Protection (1.3.6.1.5.5.7.3.4)	
#https://oidref.com/1.3.6.1.5.5.7.3

#enable PSRemote
Enable-PSRemoting -SkipNetworkProfileCheck -Force

#Self-Sign cert for WINRM server
$hostName = $env:COMPUTERNAME
$hostIP=(Get-NetAdapter| Get-NetIPAddress).IPv4Address|Out-String
if ([System.Environment]::OSVersion.Version.major -lt 10) {
    $srvCert = New-SelfSignedCertificate -DnsName $hostName,$hostIP -CertStoreLocation "CERT:\LocalMachine\My\"
}else {
    $srvCert = New-SelfSignedCertificate -DnsName $hostName,$hostIP -KeyAlgorithm RSA -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
}

#Switch WINRM to use HTTPS and disable HTTP
Get-ChildItem wsman:\localhost\Listener\ | Where-Object -Property Keys -like 'Transport=HTTP*' | Remove-Item -Recurse
New-Item -Path WSMan:\localhost\Listener\ -Transport HTTPS -Address * -CertificateThumbPrint $srvCert.Thumbprint -Force
New-NetFirewallRule -Displayname 'WinRM - Powershell remoting HTTPS-In' -Name 'WinRM - Powershell remoting HTTPS-In' -Profile Any -LocalPort 5986 -Protocol TCP
winrm set winrm/config/service '@{AllowUnencrypted="false"}'
winrm set winrm/config/client '@{AllowUnencrypted="false"}'
Restart-Service WinRM

#Setup allow certificate authenticaiton, policy, 
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true

#Disable a Remote UAC for a non-built-in Administrator
#This registry enable the "non-built-in-administrators" to elevate during remote WINRM, otherwise will be access denied. (Part of UAC behaviour)
Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1 -Force

#Setup client authentication trust mode to less restricted mode (so self-signed certs could be used)
#  https://learn.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview
#  Value 	Trust Mode                  Description
#  0 	    Machine Trust (default) 	Requires that the client certificate is issued by a certificate in the Trusted Issuers list.
#  1 	    Exclusive Root Trust 	    Requires that a client certificate chains to a root certificate contained in the caller-specified trusted issuer store. The certificate must also be issued by an issuer in the Trusted Issuers list
#  2 	    Exclusive CA Trust 	        Requires that a client certificate chain to either an intermediate CA certificate or root certificate in the caller-specified trusted issuer store.
Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name ClientAuthTrustMode -Type DWord -Value 2 -Force


####################### WINRM Client side setup #########################

#Setup WinRM client side configure and hardening
winrm set winrm/config/client '@{TrustedHosts="*"}'
winrm set winrm/config/client '@{AllowUnencrypted="false"}'

#Generate self-side client certificate for WINRM server to trust and map as local user
$winClientCert = New-SelfSignedCertificate -Type Custom -Subject "cn=PSRemote" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=PSRemote@localhost") -KeyUsage DigitalSignature,KeyEncipherment -NotAfter ((Get-Date).AddYears(10)) -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation Cert:\CurrentUser\My\
Export-Certificate -Cert $winClientCert  -FilePath .\PSRemote.cer

#Establish PSRemote session with Credential, copy the cert to WINRM server, import it, create local admin user and map the cert to it
#You have to change 192.168.3.61 to your target WINRM server IP.
#Assume your use built-in local Administrator account of WINRM server to establish the PSSession and create local account PSRemote for password-less client certificate authentication 
$SessionOption = New-PSSessionOption -SkipCNCheck -SkipCACheck -SkipRevocationCheck
$TEMPSESSION = New-PSSession -ComputerName 192.168.3.61 -SessionOption $SessionOption -UseSSL -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "192.168.3.61\administrator",(ConvertTo-SecureString -String "adminP@ssWord" -AsPlainText -Force))
Copy-Item –Path .\PSRemote.cer –Destination "C:\Windows\Temp\" –ToSession $TEMPSESSION
Invoke-Command -Session $TEMPSESSION -ScriptBlock {
    Import-Certificate -FilePath C:\Windows\Temp\PSRemote.cer -CertStoreLocation Cert:\LocalMachine\Root
    Import-Certificate -FilePath C:\Windows\Temp\PSRemote.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
    $Thumbprint=(Get-PfxCertificate C:\Windows\Temp\PSRemote.cer).Thumbprint
    $PSRemotePASSWORD=ConvertTo-SecureString -String "PSRemoteP@ssW0rd" -AsPlainText -Force
    New-LocalUser -Name "PSRemote" -Password $PSRemotePASSWORD -PasswordNeverExpires -AccountNeverExpires
    Add-LocalGroupMember -Groups Administrators -Member PSRemote
    $Credential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "192.168.3.61\PSRemote",$PSRemotePASSWORD
    New-Item -Path WSMan:\localhost\ClientCertificate -Subject "PSRemote@localhost" -URI * -Issuer $Thumbprint -Credential $Credential –Force
    Remove-Item C:\Windows\Temp\PSRemote.cer
 }
Remove-PSSession -Session $TEMPSESSION

####################### PSRemote session with client certification authentication (password-less) #########################
#$SessionOption = New-PSSessionOption -SkipCNCheck -SkipCACheck -SkipRevocationCheck
#Enter-PSSession -ComputerName <target server IP> -CertificateThumbprint <Client Certificate thumbprint> -SessionOption $SessionOption -UseSSL

Enter-PSSession -ComputerName 192.168.3.61 -CertificateThumbprint $winClientCert.Thumbprint -SessionOption $SessionOption -UseSSL
Remove-Item .\PSRemote.cer

#$Thumbprint=(Get-PfxCertificate (Get-Item .\PSRemote.cer).FullName).Thumbprint
#Enter-PSSession -ComputerName 192.168.3.61 -CertificateThumbprint $Thumbprint -SessionOption $SessionOption -UseSSL
