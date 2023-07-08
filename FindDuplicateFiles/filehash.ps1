$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

$paths = @("F:\H_uncensored_leak","D:\H","D:\Bitcomet_completed","e:","\\192.168.3.129\wd6tb","\\192.168.3.129\h")
#$paths = @("\\192.168.3.129\wd6tb","\\192.168.3.129\h")

$skip=(import-csv "G:\temp\hash.csv").path

Foreach ($path in $paths) {
    $Files=Get-ChildItem -Recurse $path
    Foreach ($file in $Files){
        if ($file.Length -gt 100000000) {           
            if ($skip.contains($file.fullname)) {
            write-host "$file.fullname already hashed,skip."
            } else {
                Get-FileHash -LiteralPath $file.FullName -Algorithm SHA1 | Export-Csv -Append -NoTypeInformation -Force -encoding utf8 -path "G:\temp\hash.csv"
                write-host $file.fullname hashed.
                pause
            }
        }
    }
}
