<#
.Synopsis 
   Sample script to decline superseded updates from WSUS, and run WSUS cleanup if any changes are made  

.DESCRIPTION 
   Declines updates from WSUS if update meets any of the following:
        - is superseded
        - is expired (as defined by Microsoft)
        - is for x86 or itanium operating systems
        - is for Windows XP
        - is a language pack
        - is for old versions of Internet Explorer (versions 7,8,9)
        - contains some country names for country specific updates not filtered by WSUS language filters.
        - is a beta update
        - is for an embedded operating system

    If an update is released for multiple operating systems, and one or more of the above criteria are met, the versions of the update that do not meet the above will not be declined by this script

.EXAMPLE 
   .\Decline-Updates -WSUSServer WSUSServer.Company.com -WSUSPort 8530

# Last updated 13 July 2016
 
# Author 
Nick Eales, Microsoft
#>


Param(    
    [Parameter(Mandatory=$false, 
    ValueFromPipeline=$true, 
    ValueFromPipelineByPropertyName=$true, 
    ValueFromRemainingArguments=$false, 
    Position=0)] 
    [string]$WSUSServer = "Localhost", #default to localhost
    [string]$Group = "All Computers", #default apply to all computers
    [int]$WSUSPort=8530,
    [switch]$reportonly
    )

Function Approve-Updates{
    Param(
        [string]$WsusServer,
        [string]$Group,
        [int]$WSUSPort,
        [switch]$ReportOnly
    )
    write-host "Connecting to WSUS Server $WSUSServer and getting list of updates"
    $Wsus = Get-WSUSserver -Name $WSUSServer -PortNumber $WSUSPort
    $ComputerTargetGroups = $wsus.GetComputerTargetGroups()
    $TargetGroup = $ComputerTargetGroups | Where {$_.Name -eq $Group}
    if($WSUS -eq $Null){
        write-error "unable to contact WSUSServer $WSUSServer"
    }else{
	    $changemade = $false        
        if($reportonly){
            write-host "ReportOnly was set to true, so not making any changes"
        }else{
		    $changemade = $true
            $Updates=$wsus.GetUpdates() | where {$_.IsDeclined -eq $false}
			write-host "$(($Updates | where {$_.IsDeclined -eq $false} | measure).Count) Updates before Approve"
			for ($i=0; $i -lt $HotfixList.Length; $i++) {
                $Updates | where {$_.KnowledgebaseArticles -match $hotfixlist[$i] -or $_.Title -match $hotfixlist[$i] -or $_.LegacyName -match $hotfixlist[$i] -or $_.AdditionalInformationUrls -match $hotfixlist[$i]} | ForEach-Object {
                #$Updates.SearchUpdates(($hotfixlist[$i])) | ForEach-Object {
                    $UpdateID = ($_ | select -ExpandProperty ID | select UpdateID)
                    $HotfixInfo = ($_ | Select-Object Title,KnowledgebaseArticles,IsApproved)
                    write-host $UpdateID
                    write-host $hotfixinfo
                    #$_.approve(“Install”,$TargetGroup)
                    #write-host $HotfixInfo
                    #write-host $UpdateID
                    [void]$updatesToApprove.Add(($UpdateID,$hotfixinfo))                    
                }           
            } 	
        }
	    
    }        
        
        write-host "$(($updatesToApprove | measure).Count) Updates to approve"
                
        #if changes were made, run a WSUS cleanup to recover disk space
        if($changemade -eq $true -and $reportonly -eq $false){
            $Updates = $wsus.GetUpdates()
            write-host "$(($Updates | where {$_.IsDeclined -eq $false} | measure).Count) Updates remaining, running WSUS cleanup"
            #Invoke-WsusServerCleanup -updateServer $WSUS -CleanupObsoleteComputers -CleanupUnneededContentFiles -CleanupObsoleteUpdates -CompressUpdates -DeclineExpiredUpdates -DeclineSupersededUpdates
        }
    }


$now=get-date -format YYYYMMDDHHMM
$script:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$script:ScriptPath = $MyInvocation.MyCommand.Path + ".log."+$now
$updatesToApprove = New-Object -TypeName System.Collections.ArrayList
$HotfixList=Get-Content .\Approve-Updates-ByHotfixID.txt 

Start-Transcript -Path $script:ScriptPath -Append -Force -NoClobber

Approve-Updates -WSUSServer $WSUSServer -Group $Group -WSUSPort $WSUSPort -reportonly:$reportonly 
$updatesToApprove | ft -AutoSize | out-file -filepath .\Approve-Updates-ByHotfixID.approved.txt -encoding ASCII

Stop-Transcript
