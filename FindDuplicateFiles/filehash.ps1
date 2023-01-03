$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

$path = "F:\H_uncensored_leak"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}

$path = "D:\H"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}

$path = "D:\Bitcomet_completed"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}

$path = "e:"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}


$path = "\\192.168.3.129\wd6tb"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}

$path = "\\192.168.3.129\h"
$Files=Get-ChildItem -Recurse $path

Foreach ($file in $Files){
    if ($file.Length -gt 100000000) {
        Get-FileHash -LiteralPath $file.FullName -File -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
    }
}
