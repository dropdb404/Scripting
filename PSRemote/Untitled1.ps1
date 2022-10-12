Enter-PSSession -ComputerName 192.168.3.114 -CertificateThumbprint 27efec660f1dbbb47bcf4a24c7c3b9b494507ed4 -SessionOption (New-PSSessionOption -UseSSL


$insecureCiphers = @(
#'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
#'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
#'TLS_ECDHE_ECDSA_WITH_AES_128_GCM',
#'TLS_ECDHE_ECDSA_WITH_AES_256_GCM',
#'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
#'TLS_RSA_RSA_WITH_AES_256_GCM_SHA384',
#'TLS_RSA_RSA_WITH_AES_128_GCM_SHA256',
#'TLS_RSA_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
'TLS_RSA_WITH_AES_128_GCM_SHA256',
'TLS_PSK_WITH_NULL_SHA384',
'TLS_PSK_WITH_NULL_SHA256'
)

$OrgKey=Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions 
$OrgKey

Foreach ($insecureCipher in $insecureCiphers) {
$NewKey=""
for ($i=0; $i -lt ($OrgKey.length -1); $i++) {
 write-host loop $OrgKey[$i]
if ($OrgKey[$i] -ne $insecureCipher) {
    $NewKey+=$OrgKey[$i] 
    $NewKey+="`r'n"
} else {
write-host "found $OrgKey[$i] need to remove"
#Write-Host "Weak cipher $insecureCipher has been disabled."
}
}
Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -name Functions $NewKey
}


Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions