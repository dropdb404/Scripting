mode 240
[string]$WSUSServer = "Localhost" #default to localhost
[string]$Group = "All Computers" #default apply to all computers
[int]$WSUSPort=8530
$now=get-date -format yyyyMMddHHmm
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptPath = $MyInvocation.MyCommand.Path + ".log."+$now
$List=Import-CSV .\Approve-Updates-ByHotfixIDv2.csv
$HotfixB4Approve = New-Object -TypeName System.Collections.ArrayList
$HotfixApproved = New-Object -TypeName System.Collections.ArrayList

Start-Transcript -Path $script:ScriptPath -Append -Force -NoClobber

write-host "Connecting to WSUS Server $WSUSServer and getting list of updates"
$Wsus = Get-WSUSserver -Name $WSUSServer -PortNumber $WSUSPort
$ComputerTargetGroups = $wsus.GetComputerTargetGroups()
$TargetGroup = $ComputerTargetGroups | Where {$_.Name -eq $Group}

if($WSUS -eq $Null){
    write-error "unable to contact WSUSServer $WSUSServer"
}else{
    #$Updates=$wsus.GetUpdates() | where {$_.IsDeclined -eq $false -and $_.IsApproved -eq $false}
    #$Updates=$wsus.GetUpdates() | where {$_.IsDeclined -eq $false}    
    $Updates=$wsus.GetUpdates()
    write-host "$($Updates.Count) Updates before Approve"
	ForEach ($KB in $List) {
        $Updates | where {$_.KnowledgebaseArticles -match $KB.KB -or $_.Title -match $KB.KB -or $_.LegacyName -match $KB.KB -or $_.AdditionalInformationUrls -match $KB.KB} | ForEach-Object {
            $KB.GUID=($_ | select -ExpandProperty ID | select UpdateID)
            $KB.Title=($_ | Select-Object Title)
            if ($_.IsApproved) {$KB.IsApproved="True"} else {$KB.IsApproved="False"}
            [void]$HotfixB4Approve.Add($KB)
            $_.approve(“Install”,$TargetGroup)
            #$_.Decline()
            if ($_.IsApproved) {$KB.IsApproved="True"} else {$KB.IsApproved="False"}
            [void]$HotfixApproved.Add($KB)
        }
    }
    #$Updates=$wsus.GetUpdates() | where {$_.IsDeclined -eq $false -and $_.IsApproved -eq $false}
    $Updates=$wsus.GetUpdates() | where {$_.IsApproved -eq $false}
    write-host "$($Updates.Count) Updates after Approve" 
}          

$HotfixB4Approve | ft -AutoSize | out-file -filepath .\HotfixB4Approve.txt -encoding ASCII
$HotfixApproved | ft -AutoSize | out-file -filepath .\HotfixApproved.txt -encoding ASCII

Stop-Transcript
