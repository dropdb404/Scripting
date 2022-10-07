# http://woshub.com/powershell-remoting-over-https/

# Make sure that your network location in Windows is set to Private or Domain (for powershell 2.0 or lower):


# $ConnectionProfiles=Get-NetConnectionProfile
# foreach ($ConnectionProfile in $ConnectionProfiles) {
#     if ($ConnectionProfile.NetworkCategory -eq 'public') {
# 	    Set-NetConnectionProfile -InterfaceAlias $ConnectionProfile.InterfaceAlias -NetworkCategory "Private"
#     }
# }

# Enable WinRM and PSRemoting using the command:
# Enable-PSRemoting -Force

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
    #netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes
    #netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new remoteip=any
    #netsh advfirewall firewall set rule name="Windows Remote Management - Compatibility Mode (HTTP-In)" new remoteip=any
    Enable-PSRemoting -Force

} elseif ($psversiontable.psversion.major -gt 2){
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    #Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
}

$hostName = $env:COMPUTERNAME
$hostIP=(Get-NetAdapter| Get-NetIPAddress).IPv4Address|Out-String
##$srvCert = New-SelfSignedCertificate -DnsName $hostName,$hostIP -KeyAlgorithm RSA -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
$srvCert = New-SelfSignedCertificate -DnsName $hostName,$hostIP -Subject $hostName -KeyAlgorithm RSA -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
#$srvCert = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -Type Custom -Subject "CN=erhugod,OU=Administrators,DC=metaconstant,DC=com" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=erhugod@localhost") -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
#$srvCert = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -Type Custom -Subject "CN=erhugod" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=erhugod") -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
#$srvCert = New-SelfSignedCertificate -DnsName "LOCALHOST",$hostIP -KeyAlgorithm RSA -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=erhugod@LOCALHOST") -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
#New-SelfSignedCertificate -Type Custom -Subject "CN=Pafftti Fuller,OU=UserAccounts,DC=corp,DC=contoso,DC=com" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=pattifuller@contoso.com") -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My"
#Client Authentication (1.3.6.1.5.5.7.3.2) 
#Server Authentication (1.3.6.1.5.5.7.3.1)
#email Protection (1.3.6.1.5.5.7.3.4)	
#https://oidref.com/1.3.6.1.5.5.7.3
#https://social.technet.microsoft.com/Forums/en-US/387f0164-07c1-48f6-a3aa-950d86a7f593/newselfsignedcertificate-using-textextension-to-create-a-cert-with-client-server-authentication?forum=winserverpowershell
#$srvCert = New-SelfSignedCertificate -DnsName $hostName,$hostIP -CertStoreLocation "cert:\LocalMachine\My" (Powershell 4.0 support fewer parameters)

dir CERT:\LocalMachine\My\

$srvCert

Get-ChildItem wsman:\localhost\Listener
Get-ChildItem wsman:\localhost\Listener\ | Where-Object -Property Keys -like 'Transport=HTTP*' | Remove-Item -Recurse
New-Item -Path WSMan:\localhost\Listener\ -Transport HTTPS -Address * -CertificateThumbPrint $srvCert.Thumbprint -Force

New-NetFirewallRule -Displayname 'WinRM - Powershell remoting HTTPS-In' -Name 'WinRM - Powershell remoting HTTPS-In' -Profile Any -LocalPort 5986 -Protocol TCP
Restart-Service WinRM
WinRM e winrm/config/listener

winrm set winrm/config/service '@{AllowUnencrypted="false"}'
winrm set winrm/config/client '@{AllowUnencrypted="false"}'

winrm set winrm/config/service/auth '@{Kerberos="false"}'

#####################################################################################################################################

#$hostName = $env:COMPUTERNAME
#$hostIP=(Get-NetAdapter| Get-NetIPAddress).IPv4Address|Out-String
#$srvCert = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -Type Custom -Subject "CN=erhugod" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=erhugod@metaconstant.com") -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
#$srvCert = New-SelfSignedCertificate -Type Custom -Subject "CN=Patti Fuller,OU=UserAccounts,DC=corp,DC=contoso,DC=com" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=pattifuller@contoso.com") -KeyUsage DigitalSignature -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -CertStoreLocation "Cert:\CurrentUser\My"
$srvCert = New-SelfSignedCertificate -Type Custom -Container test* -Subject "administrator" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=administrator@localhost") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My"
$srvCert = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=administrator@localhost") -KeyUsage DigitalSignature,KeyEncipherment,CertSign  -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "CERT:\LocalMachine\My\"
$srvCert = New-SelfSignedCertificate -DnsName "PSRemote" -Type Custom -Subject "cn=PSRemote" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=PSRemote@localhost") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -NotAfter ((Get-Date).AddYears(10)) -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My\"
$srvCert = New-SelfSignedCertificate -DnsName "PSRemote" -Type Custom -Subject "cn=PSRemote" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -KeyUsage DigitalSignature,KeyEncipherment,CertSign -NotAfter ((Get-Date).AddYears(10)) -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My\"
Export-Certificate -Cert $srvCert -FilePath .\SSL_PS_Remoting.cer
$srvCert 

#Copy the CER file to the target computer and import it using the command below (or deploy the certificate to other computers using GPO):

#####################################################################################################################################


Import-Certificate -FilePath .\SSL_PS_Remoting.cer -CertStoreLocation 'Cert:\LocalMachine\Root'
Import-Certificate -FilePath .\SSL_PS_Remoting.cer -CertStoreLocation 'Cert:\LocalMachine\Root'
Import-Certificate -FilePath .\SSL_PS_Remoting.cer -CertStoreLocation 'Cert:\LocalMachine\Root'
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true
#Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like 'CA-Name'}
#New-Item WSMan:\localhost\ClientCertificate -Subject SubjectName  -URI * -Issuer CAThumbprint -Credential (Get-Credential)

Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name ClientAuthTrustMode -Type DWord -Value 2
$srvCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Get-Item .\SSL_PS_Remoting.cer).FullName
New-Item WSMan:\localhost\ClientCertificate -Subject "simon-server.local" -URI * -Issuer "19dbd3badb4af235e4d1d70edd1618ecc13e668b" -Credential (Get-Credential) -Force

#This registry enable the "non-built-in-administrators" to elevate during remote WINRM, otherwise will be access denied. (Part of UAC behaviour)
#How to Disable a Remote UAC for a non-built-in Administrator
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name ClientAuthTrustMode -Type DWord -Value 2

#####################################################################################################################################


dir -recurse | where {$_.Thumbprint -eq “b9e5ca991422a0a30394b995cfa5a352383f20b5”} | Format-List -property



winrm s winrm/config/client '@{TrustedHosts="*"}'
#winrm s winrm/config/client '@{TrustedHosts=""}'
winrm set winrm/config/service '@{AllowUnencrypted="false"}'
winrm set winrm/config/client '@{AllowUnencrypted="false"}'

Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name ClientAuthTrustMode -Type DWord -Value 2


#Import-Certificate -FilePath .\SSL_PS_Remoting.cer -CertStoreLocation Cert:\LocalMachine\root\
#Import-Certificate -FilePath .\SSL_PS_Remoting.cer -CertStoreLocation Cert:\CurrentUser\My\
Get-ChildItem Cert:\CurrentUser\My
$SessionOption = New-PSSessionOption -SkipCNCheck -SkipCACheck -SkipRevocationCheck
#Enter-PSSession -Computername 192.168.13.4 -UseSSL -Credential maxbak -SessionOption $SessionOption
#Enter-PSSession -Computername 192.168.3.109 -UseSSL -Credential administrator -SessionOption (New-PSSessionOption -SkipCNCheck -SkipCACheck -SkipRevocationCheck)
Enter-PSSession -ComputerName 192.168.3.61 -CertificateThumbprint '8A57D93BE81A450B695D3749CF28DB5184C9F96E' -SessionOption $SessionOption -UseSSL


#############################
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#############################

New-SelfSignedCertificate -Subject 'CN=ServerB.domain.com' -TextExtension '2.5.29.37={text}1.3.6.1.5.5.7.3.1'
PS D:\> New-SelfSignedCertificate  -DnsName "$ENV:COMPUTERNAME" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter ((Get-Date).AddYears(10)) -CertStoreLocation "cert:\LocalMachine\My"
Thumbprint
----------
F3880C95203CA33770BFC314FC5923EF74C47000


Get-ChildItem Cert:\LocalMachine\My\D312D37135571305DB78D940EF021E7DD3BC55EE | Remove-Item
Get-ChildItem Cert:\LocalMachine\root\D312D37135571305DB78D940EF021E7DD3BC55EE | Remove-Item
7F0FD90523B93159D59AC7A41297E3D679AF0A23


$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Invoke-Command -ComputerName 192.168.3.61 -UseSSL -ScriptBlock { Get-HotFix } -SessionOption $so -Credential erhugod


$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck



Invoke-Command -ComputerName 192.168.3.61 -UseSSL -ScriptBlock $ScriptBlock -SessionOption $so -Credential erhugod



New-SelfSignedCertificate -DnsName "www.fabrikam.com", "www.contoso.com" -CertStoreLocation "cert:\LocalMachine\My"

This example creates a self-signed SSL server certificate in the computer MY store with the subject alternative name set to www.fabrikam.com, www.contoso.com and Subject and Issuer name set to www.fabrikam.com.

New-SelfSignedCertificate -Type Custom -Subject "E=patti.fuller@contoso.com,CN=Patti Fuller" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.4","2.5.29.17={text}email=patti.fuller@contoso.com&upn=pattifuller@contoso.com") -KeyAlgorithm RSA -KeyLength 2048 -SmimeCapabilities -CertStoreLocation "Cert:\CurrentUser\My"

This example creates a self-signed client authentication certificate in the user MY store. The certificate uses the default provider, which is the Microsoft Software Key Storage Provider. The certificate uses an RSA asymmetric key with a key size of 2048 bits. The certificate has a subject alternative name of pattifuller@contoso.com.

New-SelfSignedCertificate -Type Custom -Subject "CN=Patti Fuller,OU=UserAccounts,DC=corp,DC=contoso,DC=com" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=pattifuller@contoso.com") -KeyUsage DigitalSignature -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -CertStoreLocation "Cert:\CurrentUser\My"

This example creates a self-signed client authentication certificate in the user MY store. The certificate uses the default provider, which is the Microsoft Software Key Storage Provider. The certificate uses an elliptic curve asymmetric key and the curve parameters nist256, which creates a 256-bit key. The subject alternative name is pattifuller@contoso.com.

The certificate expires in one year.

winrm delete winrm/config/service/certmapping?Issuer=‎87d604dae22d91ee90f10a7dd91c33fc3093fd9b+Subject=PC01+URI=*


New-Item WSMan:\localhost\ClientCertificate -Subject 'erhugod' -URI * -Issuer '7911E35704B8AF5B218EB1A783E4869B2B3750FC' -Credential (Get-Credential) -Force