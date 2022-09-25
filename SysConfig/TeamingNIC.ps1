$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
$List=Import-CSV .\TeamingNIC.csv

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber

Write-Output ($List | FT -AutoSize)
Get-NetAdapter | Select Name,MacAddress | Sort-object Name | FT -AutoSize

ForEach ($Item in $List) {
	New-NetLbfoTeam -name $Item.TeamName -TeamMembers $Item.ActiveMember,$Item.StandbyMember -LoadBalancingAlgorithm $Item.LoadBalancingAlgorithm -TeamingMode $Item.TeamingMode -Confirm:$false
	Set-NetLbfoTeamMember -Name $Item.StandbyMember -administrativemode standby
}

Get-NetAdapter | Select Name,MacAddress | Sort-object Name | FT -AutoSize
Start-Sleep 15
Get-NetLbfoTeam | FT -AutoSize

Stop-Transcript