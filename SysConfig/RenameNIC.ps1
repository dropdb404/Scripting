$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptLog = $MyInvocation.MyCommand.Path + ".log."+$now
$List=Import-CSV .\RenameNIC.csv
$NICHW=Get-NetAdapterHardwareInfo

Start-Transcript -Path $script:ScriptLog -Append -Force -NoClobber

Write-Output $List
Write-Output $NICHW

ForEach ($Item in $List) {
    ForEach ($NIC in $NICHW) {
        if ((([string]::IsNullOrEmpty($Item.slot) -and [string]::IsNullOrEmpty($NIC.slot)) or ($NIC.Slot -eq $Item.Slot)) -and $NIC.Function -eq $Item.Function) {Rename-NetAdapter -Name $NIC.Name -NewName $Item.Name}
    }
}

Write-Output $List
Get-NetAdapterHardwareInfo

Stop-Transcript