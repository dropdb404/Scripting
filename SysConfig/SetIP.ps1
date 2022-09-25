$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
$List=Import-CSV .\SetIP.csv

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber

Write-Output ($List | FT -AutoSize)
Get-NetIPAddress -AddressFamily IPv4 | select InterfaceAlias,IPaddress,PrefixLength,ifIndex | FT -AutoSize
Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore | FT -AutoSize

ForEach ($Item in $List) {
	If ($Item.DefaultGateway -ne "") {New-NetIPAddress –IPAddress $Item.IPAddress –InterfaceAlias $Item.InterfaceAlias –PrefixLength $Item.PrefixLength -DefaultGateway $Item.DefaultGateway -AddressFamily $Item.AddressFamily}
	else {New-NetIPAddress –IPAddress $Item.IPAddress –InterfaceAlias $Item.InterfaceAlias –PrefixLength $Item.PrefixLength -AddressFamily $Item.AddressFamily}
	
	#Set-DNSClientServerAddress –InterfaceAlias $Item.InterfaceAlias –ServerAddresses (“10.0.0.1”,”10.0.0.2”)
}

Get-NetIPAddress -AddressFamily IPv4 | select InterfaceAlias,IPaddress,PrefixLength,ifIndex | FT -AutoSize
Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore | FT -AutoSize

Stop-Transcript