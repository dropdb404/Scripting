if ((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").proxyenable -eq 1) {
    $proxyoverride=((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").proxyoverride)
    if (!($proxyoverride | Select-String "10.194.117.115")) {
        $new+="10.194.117.115;" + $proxyoverride
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name proxyoverride -Value $new
    }
}
