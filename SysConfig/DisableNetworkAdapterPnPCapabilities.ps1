#--------------------------------------------------------------------------------- 
#The sample scripts are not supported under any Microsoft standard support 
#program or service. The sample scripts are provided AS IS without warranty  
#of any kind. Microsoft further disclaims all implied warranties including,  
#without limitation, any implied warranties of merchantability or of fitness for 
#a particular purpose. The entire risk arising out of the use or performance of  
#the sample scripts and documentation remains with you. In no event shall 
#Microsoft, its authors, or anyone else involved in the creation, production, or 
#delivery of the scripts be liable for any damages whatsoever (including, 
#without limitation, damages for loss of business profits, business interruption, 
#loss of business information, or other pecuniary loss) arising out of the use 
#of or inability to use the sample scripts or documentation, even if Microsoft 
#has been advised of the possibility of such damages 
#--------------------------------------------------------------------------------- 

#requires -Version 2.0

Function Disable-OSCNetAdapterPnPCaptitlies
{

$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}

Start-Transcript -Path $LogPath\DisableNetworkAdapterPnPCapabilities.log -Append -Force -NoClobber

	#find only physical network,if value of properties of adaptersConfigManagerErrorCode is 0,  it means device is working properly. 
	#even covers enabled or disconnected devices.
	#if the value of properties of configManagerErrorCode is 22, it means the adapter was disabled. 
	$PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter|Where-Object{$_.PNPDeviceID -notlike "ROOT\*" `
	-and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22} 
	
	Foreach($PhysicalAdapter in $PhysicalAdapters)
	{
		$PhysicalAdapterName = $PhysicalAdapter.Name
		#check the unique device id number of network adapter in the currently environment.
		$DeviceID = $PhysicalAdapter.DeviceID
		If([Int32]$DeviceID -lt 10)
		{
			$AdapterDeviceNumber = "000"+$DeviceID
		}
		Else
		{
			$AdapterDeviceNumber = "00"+$DeviceID
		}
		
		#check whether the registry path exists.
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
		If(Test-Path -Path $KeyPath)
		{
			$PnPCapabilitiesValue = (Get-ItemProperty -Path $KeyPath).PnPCapabilities
			If($PnPCapabilitiesValue -eq 280)
			{
				Write-Warning """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" has been disabled already."
			}
			If($PnPCapabilitiesValue -eq 0)
			{
				#check whether change value was successed.
				Try
				{	
					#setting the value of properties of PnPCapabilites to 280 (windows 2012R2), it will disable save power option.
					Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 280 | Out-Null
					Write-Host """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" was disabled."
		        }
				Catch
				{
					Write-Host "Setting the value of properties of PnpCapabilities failed." -ForegroundColor Red
				}
			}
			If($PnPCapabilitiesValue -eq $null)
			{
				Try
				{
					New-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 280 -PropertyType DWord | Out-Null
					Write-Host """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" was disabled."

				}
				Catch
				{
					Write-Host "Setting the value of properties of PnpCapabilities failed." -ForegroundColor Red
				}
			}
		}
		Else
		{
			Write-Warning "The path ($KeyPath) not found."
		}
	}
Stop-Transcript
}

Disable-OSCNetAdapterPnPCaptitlies