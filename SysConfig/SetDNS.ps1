$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
$List=Import-CSV .\SetDNS.csv

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber

Write-Output ($List | SLS $env:computername | FT -AutoSize)
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses |FT -AutoSize
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -expandProperty ServerAddresses |FT -AutoSize

ForEach ($Item in $List) {
	$DNS=""
	for ($i=2;i -le $Item.length;$i++){
		if ($Item.(DNS($i)) -ne "") {
			$DNS+=$Item.(DNS($i))
			$DNS+=","	
		}
	}
	Set-DNSClientServerAddress –InterfaceAlias $Item.InterfaceAlias –ServerAddresses ($DNS)
}

Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses |FT -AutoSize
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -expandProperty ServerAddresses |FT -AutoSize

Stop-Transcript