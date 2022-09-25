param($global:RestartRequired=0,
        $global:MoreUpdates=0,
        $global:MaxCycles=5,
		$MaxUpdatesPerCycle=300)

#$Logfile = "C:\Windows\Temp\win-updates.log"
#$Logfile = "C:\hotfix\checking\winupdate.log"

$now = Get-Date -format yyyyMMddHHmm
If(test-path c:\hotfix\checking) {
		$Logfile = "C:\hotfix\checking\winupdate.log."+$now
	} Else {
		$Logfile = "C:\Windows\Temp\winupdate.log."+$now
	}

function LogWrite {
   Param ([string]$logstring)
   $now = Get-Date -format s
   Add-Content $Logfile -value "$now $logstring"
   write-host $now $logstring
}

function Check-ContinueRestartOrEnd() {
    $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $RegistryEntry = "InstallWindowsUpdates"
    switch ($global:RestartRequired) {
        0 {			
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            if ($prop) {
				LogWrite "Restart Registry Entry Exists - Removing It"
                Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
                schtasks /Change /TN "WSUSLOOP" /DISABLE
            }
            
			LogWrite "No Restart Required"
            Check-WindowsUpdates
            
            if (($global:MoreUpdates -eq 1) -and ($script:Cycles -le $global:MaxCycles)) {
                Install-WindowsUpdates
            } elseif ($script:Cycles -gt $global:MaxCycles) {
				LogWrite "Exceeded Cycle Count - Stopping"
			} else {
                LogWrite "Done Installing Windows Updates"
            }
        }
        1 {
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            if (-not $prop) {
				LogWrite "Restart Registry Entry Does Not Exist - Creating It"
#                Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $($script:ScriptPath) -MaxUpdatesPerCycle $($MaxUpdatesPerCycle)"
                Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command {Add-Content $Logfile -value ""user logined and trigger Run""}"
            } else {
				LogWrite "Restart Registry Entry Exists Already"
            }
            
#            Restart-Computer -ThrottleLimit 10 -force
			#shutdown /r /f /d p:2:17 /t 10 /c "Reboot after WSUSLOOP" 2>$null
			if ($LastExitCode -ne 0) {
				#write-host "Cannot reboot $PC ($LastExitCode)" -ForegroundColor black -BackgroundColor red
				LogWrite "Cannot reboot $env:computername ($LastExitCode)"
			} else {
				LogWrite "$env:username,$env:computername,Reboot Sent"
			}
        }
        default { 
			LogWrite "Unsure If A Restart Is Required"
#            schtasks /Change /TN "WSUSLOOP" /DISABLE
            break
        }
    }
}

function Install-WindowsUpdates() {
    $script:Cycles++
	LogWrite "Evaluating Available Updates with limit of $($MaxUpdatesPerCycle):"
    $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    $script:i = 0;
    $CurrentUpdates = $SearchResult.Updates
    while($script:i -lt $CurrentUpdates.Count -and $script:CycleUpdateCount -lt $MaxUpdatesPerCycle) {
        $Update = $CurrentUpdates.Item($script:i)
        if (($Update -ne $null) -and (!$Update.IsDownloaded)) {
            [bool]$addThisUpdate = $false
            if ($Update.InstallationBehavior.CanRequestUserInput) {
                LogWrite "> Skipping: $($Update.Title) because it requires user input"
            } else {
                if (!($Update.EulaAccepted)) {
                    LogWrite "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license."
                    $Update.AcceptEula()
                    [bool]$addThisUpdate = $true
                    $script:CycleUpdateCount++
                } else {
                    [bool]$addThisUpdate = $true
                    $script:CycleUpdateCount++
                }
            }

            if ([bool]$addThisUpdate) {
                LogWrite "Adding: $($Update.Title)"
                $UpdatesToDownload.Add($Update) |Out-Null
            }
        }
        $script:i++
    }	

    
    if ($UpdatesToDownload.Count -eq 0) {
		LogWrite "No Updates To Download..."
    } else {
        LogWrite 'Downloading Updates...'
		$script:successful = $FALSE
		$script:attempts = 0
		$script:maxAttempts = 12
		while (-not $script:successful -and $script:attempts -lt $script:maxAttempts) {
			try {
				$Downloader = $UpdateSession.CreateUpdateDownloader()
				$Downloader.Updates = $UpdatesToDownload
				$Downloader.Download()
				$script:successful = $TRUE
			} catch {
				LogWrite $_.Exception | Format-List -force
				LogWrite "Error downloading updates. Retrying in 30s."
				$script:attempts = $script:attempts + 1
				Start-Sleep -s 30
			}
		}
    }
	
    $UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    [bool]$rebootMayBeRequired = $false
	LogWrite 'The following updates are downloaded and ready to be installed:'
    foreach ($Update in $SearchResult.Updates) {
        if (($Update.IsDownloaded)) {
			LogWrite "> $($Update.Title)"
            $UpdatesToInstall.Add($Update) |Out-Null
              
            if ($Update.InstallationBehavior.RebootBehavior -gt 0){
                [bool]$rebootMayBeRequired = $true
            }
        }
    }
    
    if ($UpdatesToInstall.Count -eq 0) {
		LogWrite 'No updates available to install...'
        $global:MoreUpdates=0
        $global:RestartRequired=0
        break
    }

    if ($rebootMayBeRequired) {
		LogWrite 'These updates may require a reboot'
        $global:RestartRequired=1
    }
	
	LogWrite 'Installing updates...'
  
    $Installer = $script:UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallationResult = $Installer.Install()
  
	LogWrite "Installation Result: $($InstallationResult.ResultCode)"
	LogWrite "Reboot Required: $($InstallationResult.RebootRequired)"
	LogWrite 'Listing of updates installed and individual installation results:'   
    if ($InstallationResult.RebootRequired) {
        $global:RestartRequired=1
    } else {
        $global:RestartRequired=0
    }
    
    for($i=0; $i -lt $UpdatesToInstall.Count; $i++) {
        New-Object -TypeName PSObject -Property @{
            Title = $UpdatesToInstall.Item($i).Title
            Result = $InstallationResult.GetUpdateResult($i).ResultCode
        }
		LogWrite "Item: " $UpdatesToInstall.Item($i).Title
        LogWrite "Result: " $InstallationResult.GetUpdateResult($i).ResultCode;
    }
	
    Check-ContinueRestartOrEnd
}

function Check-WindowsUpdates() {
	LogWrite "Checking For Windows Updates"
    $Username = $env:USERDOMAIN + "\" + $env:USERNAME
 
    New-EventLog -Source $ScriptName -LogName 'Windows Powershell' -ErrorAction SilentlyContinue
 
    $Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()

    Write-EventLog -LogName 'Windows Powershell' -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
    LogWrite $Message

    $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
    $script:successful = $FALSE
    $script:attempts = 0
    $script:maxAttempts = 12
    while(-not $script:successful -and $script:attempts -lt $script:maxAttempts) {
        try {
            $script:SearchResult = $script:UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            $script:successful = $TRUE
        } catch {
            LogWrite $_.Exception | Format-List -force
            LogWrite "Search call to UpdateSearcher was unsuccessful. Retrying in 10s."
            $script:attempts = $script:attempts + 1
            Start-Sleep -s 10
        }
    }

    if ($SearchResult.Updates.Count -ne 0) {
        $Message = "There are " + $SearchResult.Updates.Count + " more updates."
        LogWrite $Message
        try {
            for($i=0; $i -lt $script:SearchResult.Updates.Count; $i++) {
              LogWrite $script:SearchResult.Updates.Item($i).Title
              LogWrite $script:SearchResult.Updates.Item($i).Description
              LogWrite $script:SearchResult.Updates.Item($i).RebootRequired
              LogWrite $script:SearchResult.Updates.Item($i).EulaAccepted
			}
            $global:MoreUpdates=1
        } catch {
            LogWrite $_.Exception | Format-List -force
            LogWrite "Showing SearchResult was unsuccessful. Rebooting."
            $global:RestartRequired=1
            $global:MoreUpdates=0
            Check-ContinueRestartOrEnd
            LogWrite "Show never happen to see this text!"
#            Restart-Computer -ThrottleLimit 10 -force
			#shutdown /r /f /d 2:17 /t 10 /c "Reboot as failed list WSUS SearchResult" 2>$null
        }
    } else {
        LogWrite "There are no applicable updates"
        $global:RestartRequired=0
        $global:MoreUpdates=0
    }
}

$script:ScriptName = $MyInvocation.MyCommand.ToString()
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
$script:UpdateSession.ClientApplicationID = 'Packer Windows Update Installer'
$script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
$script:SearchResult = New-Object -ComObject 'Microsoft.Update.UpdateColl'
$script:Cycles = 0
$script:CycleUpdateCount = 0


$script:ServiceName1 = "wuauserv"
$script:ServiceName2 = "bits"

LogWrite "Stopping wuauserv and bits service"
Stop-Service $script:ServiceName1 -Force
Stop-Service $script:ServiceName2 -Force
Start-Sleep -S 120
Set-Service -Name $script:ServiceName1 -StartupType Manual -Status Stopped
Set-Service -Name $script:ServiceName2 -StartupType Manual -Status Stopped
LogWrite "Starting wuauserv and bits service"
Start-Service -Name $script:ServiceName1
Start-Service -Name $script:ServiceName2
Start-Sleep -S 60
LogWrite "wuauclt detect now"
wuauclt /detectnow
Start-Sleep -S 600
LogWrite "wuauclt report now"
wuauclt /reportnow
Start-Sleep -S 60

LogWrite "Start Check Windows Updates"
Check-WindowsUpdates
if ($global:MoreUpdates -eq 1) {
    Install-WindowsUpdates
} else {
    Check-ContinueRestartOrEnd
}
