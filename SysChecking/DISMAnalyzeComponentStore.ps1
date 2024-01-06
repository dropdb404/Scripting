$DISMAnalyze = cmd /r 'dism /Online /Cleanup-Image /AnalyzeComponentStore'

if (($DISMAnalyze[$DISMAnalyze.count -14] -split " : ")[0] -like "Windows Explorer Reported Size of Component Store"){
    $WindowsExplorerReportedSizeofComponentStore=($DISMAnalyze[$DISMAnalyze.count -14] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -12] -split " : ")[0] -like "Actual Size of Component Store"){
    $ActualSizeofComponentStore=($DISMAnalyze[$DISMAnalyze.count -12] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -10] -split " : ")[0] -like "*Shared with Windows"){
    $SharedwithWindows=($DISMAnalyze[$DISMAnalyze.count -10] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -9] -split " : ")[0] -like "*Backups and Disabled Features"){
    $BackupsandDisabledFeatures=($DISMAnalyze[$DISMAnalyze.count -9] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -8] -split " : ")[0] -like "*Cache and Temporary Data"){
    $CacheandTemporaryData=($DISMAnalyze[$DISMAnalyze.count -8] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -6] -split " : ")[0] -like "Date of Last Cleanup"){
    $DateofLastCleanup=($DISMAnalyze[$DISMAnalyze.count -6] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -4] -split " : ")[0] -like "Number of Reclaimable Packages"){
    $NumberofReclaimablePackages=($DISMAnalyze[$DISMAnalyze.count -4] -split " : ")[1]
}

if (($DISMAnalyze[$DISMAnalyze.count -3] -split " : ")[0] -like "Component Store Cleanup Recommended"){
    $ComponentStoreCleanupRecommended=($DISMAnalyze[$DISMAnalyze.count -3] -split " : ")[1]
}

$result=[PSCustomObject]@{
    Hostname=$env:COMPUTERNAME;
    WindowsExplorerReportedSizeofComponentStore=$WindowsExplorerReportedSizeofComponentStore;
    ActualSizeofComponentStore=$ActualSizeofComponentStore;
    SharedwithWindows=$SharedwithWindows;
    BackupsandDisabledFeatures=$BackupsandDisabledFeatures;
    CacheandTemporaryData=$CacheandTemporaryData;
    DateofLastCleanup=$DateofLastCleanup;
    NumberofReclaimablePackages=$NumberofReclaimablePackages;
    ComponentStoreCleanupRecommended=$ComponentStoreCleanupRecommended  
}

$result