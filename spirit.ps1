###This script allows you to remove unwanted Apps that come with Windows within a GUI. ###
###Press <CTRL> if you want to select and remove mutliple apps at the same time ###
###INFO: Provisoned apps are applications that Windows will attempt to reinstall during updates, or when a new user account is made. If you remove these you will have to install them manually through the Store app when making new accounts.
Get-AppxProvisionedPackage -online | Out-GridView -PassThru | Remove-AppxProvisionedPackage -online

###This script allows you to remove unwanted Apps that come with Windows within a GUI. ###
###Press <CTRL> if you want to select and remove mutliple apps at the same time

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
[System.Windows.Forms.MessageBox]::Show('Press <CTRL> if you want to select and remove mutliple apps at the same time.')
Get-AppxPackage -AllUsers | Out-GridView -PassThru | Remove-AppxPackage



###This script will remove and disable OneDrive integration. ###
###Author of this script: https://github.com/W4RH4WK/Debloat-Windows-10###
###Requires -RunSilent

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}


###This script will run an update check for Microsoft Store apps.###

$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_EnterpriseModernAppManagement_AppManagement01"
$wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
$result = $wmiObj.UpdateScanMethod()

###Requires -RunSilent

###Certain elements of Windows 11, such as the News and interests widget, open links in Edge regardless of which browser is set as default. This is done through the use of edge:// protocol links. ###
###This script intercepts URIs that force-open web links in Microsoft Edge and redirects it to the system's default web browser ###
###To revert to Edge as the default handler for web searches, all you have to do is run the script again. ###
###Projects page: https://github.com/AveYo/fox/blob/main/ChrEdgeFkOff.cmd
@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit/b
#:: double-click to run or just copy-paste into powershell - it's a standalone hybrid script
#::
#:: ChrEdgeFkOff - make start menu web search or widgets links open in your chosen default browser - by AveYo
#:: v2.0 only redirects microsoft-edge: links, no longer blocks msedge.exe (with a junction trick)    
#:: 
$_Paste_in_Powershell = {
$vbs = @'
' ChrEdgeFkOff - make start menu web search or widgets links open in your chosen default browser - by AveYo  
Dim C, A: For Each i in WScript.Arguments: A = A&" """&i&"""": Next
Set W = CreateObject("WScript.Shell"): Set E = W.Environment( "Process" ): E("CL") = A : C = ""
C = C & "$U = get-itemproperty 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' 'ProgID';"
C = C & "$C = get-itemproperty -lit $('Registry::HKCR\' + $U.ProgID + '\shell\open\command') '(Default)' -ea 0;"
C = C & "$UserChoice = ($C.'(Default)'-split [char]34,3)[1]; $MSE = $env:CL -replace '\\Microsoft\\Edge', '\Microsoft\ChrEdge';"
C = C & "if ($UserChoice -like '*Microsoft\Edge\Application\msedge.exe*') {iex('&'+$MSE); return 2};"
C = C & "if ($env:CL -notlike '*microsoft-edge:*') {iex('&'+$MSE); return 1};"
C = C & "start $UserChoice $([uri]::unescapedatastring(($env:CL-split'(?=http[s]?)')[1] -replace [char]34)+' '); return 0"
W.Run "powershell -nop -c " & C, 0, False
'@ 
$DATA = [Environment]::GetFolderPath('CommonApplicationData'); $file = join-path $DATA "ChrEdgeFkOff.vbs"
$PROF = [Environment]::GetFolderPath('ProgramFiles'+('x86','')[![Environment]::Is64BitOperatingSystem])
$EDGE = join-path $PROF 'Microsoft\Edge\'; $CREDGE = join-path $PROF 'Microsoft\ChrEdge\'
$IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe'
if (test-path "$IFEO\0") {
  remove-item "$IFEO\0" -rec -force -ea 0 >''; remove-itemproperty $IFEO 'Debugger' -force -ea 0 >'' 
  del $file -force -ea 0 >''; rmdir $CREDGE -rec -force -ea 0 >'';
  write-host -fore 0xf -back 0xd "`n ChrEdgeFkOff v2.0 [REMOVED] run again to install "
} else {                              
  new-item "$IFEO\0" -force -ea 0 >''; remove-itemproperty $IFEO 'Debugger' -force -ea 0 >'' 
  [io.file]::WriteAllText($file, $vbs) >''; start -nonew cmd "/d/x/r mklink /J ""$CREDGE"" ""$EDGE"" >nul"
  set-itemproperty $IFEO 'UseFilter' 1 -type dword -force -ea 0
  set-itemproperty "$IFEO\0" 'FilterFullPath' $(join-path $PROF 'Microsoft\Edge\Application\msedge.exe') -force -ea 0 
  set-itemproperty "$IFEO\0" 'Debugger' "wscript $file //B //T:5" -force -ea 0 
  write-host -fore 0xf -back 0x2 "`n ChrEdgeFkOff v2.0 [INSTALLED] run again to remove " } ; timeout /t 5
} ; start -verb runas powershell -args "-nop -c & {`n`n$($_Paste_in_Powershell-replace'"','\"')}"
$_Press_Enter
#::


###Microsoft added the “Ultimate Performance mode” power scheme to Windows 10 April 2018 Update to optimize the system’s performance, especially high-end PCs.###
###The “Ultimate Performance” power plan option may not be available on some systems, especially if you are using a laptop.###
###Requires -RunSilent

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do you want to enable the Ultimate Performance power plan?','ThisIsWin11','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 

[System.Windows.Forms.MessageBox]::Show('Power plan has been successfully enabled. Now open Settings and navigate to System > Power & sleep > Additional Power Settings and enable the Ultimate Performance power plan.')
 }

'No'{}

}


###This tweak will turn off unnecessary Windows 11 services.###
###A detailed explantation of each service can be found here: https://nerdschalk.com/what-windows-11-services-to-disable-safely-and-how###
###- Connected User Experiences and Telemetry
###- FAX
###- AllJoyn Router Service
###- Program Compatibility Assistant Service
###- Device Management Wireless Application Protocol (WAP) Push message Routing Service
###- Remote Registry
###- Windows Media Player Network Sharing Service
###- Windows Image Acquisition
###- Xbox Services
###- Windows Network Data Usage Monitor###

$services = @(
    "DiagTrack"                                # Connected User Experiences and Telemetry. If you're concerned with privacy and don't want to send usage data to Microsoft for analysis, then this service is one to go.
	"fxssvc.exe"				               # Fax. As its name suggests, this is a service needed only if you want to send and receive faxes.
    "AxInstSV"								   # AllJoyn Router Service. This is a service that lets you connect Windows to the Internet of Things and communicate with devices such as smart TVs, refrigerators, light bulbs, thermostats, etc.
    "PcaSvc"                                   # Program Compatibility Assistant Service (Unless you're still using legacy software on your Windows 11 PC, you can easily turn off this service. This service lets you detect software incompatibility issues for old games and software. But if you're using programs and apps built for Window 11, go ahead and disable it.)
	"dmwappushservice"						   # Device Management Wireless Application Protocol (WAP) Push message Routing Service. This service is another service that helps to collect and send user data to Microsoft. Strengthen your privacy by disabling it, it is recommended that you do so. 
    "Remote Registry"                          # Remote Registry. This service lets any user access and modify the Windows registry. It is highly recommended that you disable this service for security purposes. Your ability to edit the registry locally (or as admin) won't be affected. 
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    "StiSvc"                                   # Windows Image Acquisition. This service is important for people who connect scanners and digital cameras to their PC. But if you don't have one of those, or are never planning on getting one, disable it by all means.
    "XblAuthManager"                           # Xbox Live Auth Manager. If you don't use Xbox app to play games, then you don't need any of the Xbox services.
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "ndu"                                      # Windows Network Data Usage Monitor
	#"wisvc"								   # Windows Insider Service. Disable this service only if you're not in the Windows Insider program. Currently, as Windows 11 is only available through it, you shouldn't disable it. 
)	

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

###Requires -RunSilent

###This is a template which will block and disable telemetry features of the following apps: ###
###- Block Google Chrome Software Reporter Tool
# The Software Reporter Tool (also known as Chrome Cleanup Tool and Software Removal Tool, the executable file is software_reporter_tool.exe), is a tool that Google distributes with the Google Chrome web browser. 
# It is a part of Google Chrome's Clean up Computer feature which scans your computer for harmful software. If this tool finds any harmful app or extension which can cause problems, it removes them from your computer. 
# Anything that interferes with a user's browsing experience may be removed by the tool.
# Its disadvantages, high CPU load or privacy implications, may be reason enough to block it from running. This script will disable the software_reporter_tool.exe in a more cleaner way using Image File Execution Options Debugger value. 
# Setting this value to an executable designed to kill processes disables it. Chrome won't re-enable it with almost each update. Next to this, it will also be disabled per default in Registry.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupEnabled -Type String -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupReportingEnabled -Type String -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name MetricsReportingEnabled -Type String -Value 0 -Force
# This will disable the software_reporter_tool.exe in a more cleaner way using Image File Execution Options Debugger value. 
# Setting this value to an executable designed to kill processes disables it. Chrome won't re-enable it with almost each update. 
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe")) {
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Force | Out-Null
Write-Output "Google Chrome Software Reporter Tool has been successfully blocked."
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name "Debugger" -Type String -Value %windir%\System32\taskkill.exe -Force 

###- Disable Mozilla Firefox telemetry
# Firefox 75 comes with a new telemetry agent that sends information about your operating system and your default browser to Firefox every day. 
# The information collected is sent as a background telemetry ping every 24 hours to Mozilla.
# Mozilla has introduced a Windows group policy that prevents the default-browser-agent.exe executable from sending your default browser info. 
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableTelemetry -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableDefaultBrowserAgent -Type DWord -Value 1 -Force

###- Disable CCleaner Monitoring
# Since Avast acquired Piriform, the popular system cleaning software CCleaner has become bloated with malware, bundled PUPs(potentially unwanted programs), and an alarming amount of pop-up ads.
# If you're highly dependent on CCleaner you can disable with this script the CCleaner Active Monitoring ("Active Monitoring" feature has been renamed with v5.46 to "Smart Cleaning"), 
# automatic Update check and download function, trial offer notifications, the new integrated Software Updater and the privacy option to "Help Improve CCleaner by sending anonymous usage data".
Stop-Process -name CCleaner*
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name Monitoring -Type String -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name HelpImproveCCleaner -Type String -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name SystemMonitoring -Type String -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name UpdateAuto -Type String -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name UpdateCheck -Type String -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name CheckTrialOffer -Type String -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name (Cfg)GetIpmForTrial -Type String -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name (Cfg)SoftwareUpdater -Type String -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name (Cfg)SoftwareUpdaterIpm -Type String -Value 0 -Force
Get-ScheduledTask -TaskName "CCleaner Update" | Disable-ScheduledTask

###- Disable Dropbox Update service
# This will disable Dropbox auto update service
Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineCore" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineUA" | Disable-ScheduledTask

###- Disable Google Update service
# This will disable Google update service
Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" | Disable-ScheduledTask

###- Disable Media Player telemetry
# This will disable Media Player telemetry
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name UsageTracking -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name PreventCDDVDMetadataRetrieval -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name PreventMusicFileMetadataRetrieval -Type DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name PreventRadioPresetsRetrieval -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name DisableOnline -Type DWord -Value 1 -Force
Set-Service WMPNetworkSvc -StartupType Disabled

###- Disable Microsoft Office telemetry
# This will disable Microsoft Office telemetry (supports Microsoft Office 2013 and 2016)
Get-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" | Disable-ScheduledTask
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name Enablelogging -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name EnableUpload -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name Enablelogging -Type DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name EnableUpload -Type DWord -Value 0 -Force
###
###Requires -RunSilent

###This will use classic Disk clean-up utility aka Cleanmgr.exe to clear unnecessary files from your computer's hard disk instead of Microsoft's replacement "Storage Sense app" which is part of the Settings app.###
###This script will use command-line options to specify that Cleanmgr.exe cleans up all areas expect Recycle Bin and Previous Windows Installations.###
###Requires -RunSilent

Requires -RunAsAdministrator

$SageSet = "StateFlags0099"
$Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
$Locations= @(
    "Active Setup Temp Folders"
    "BranchCache"
    "Downloaded Program Files"
    "GameNewsFiles"
    "GameStatisticsFiles"
    "GameUpdateFiles"
    "Internet Cache Files"
    "Memory Dump Files"
    "Offline Pages Files"
    "Old ChkDsk Files"
    "D3D Shader Cache"
    "Delivery Optimization Files"
    "Diagnostic Data Viewer database files"
    #"Previous Installations"
    #"Recycle Bin"
    "Service Pack Cleanup"
    "Setup Log Files"
    "System error memory dump files"
    "System error minidump files"
    "Temporary Files"
    "Temporary Setup Files"
    "Temporary Sync Files"
    "Thumbnail Cache"
    "Update Cleanup"
    "Upgrade Discarded Files"
    "User file versions"
    "Windows Defender"
    "Windows Error Reporting Archive Files"
    "Windows Error Reporting Queue Files"
    "Windows Error Reporting System Archive Files"
    "Windows Error Reporting System Queue Files"
    "Windows ESD installation files"
    "Windows Upgrade Log Files"
)

# -ea silentlycontinue will supress error messages
ForEach($Location in $Locations) {
    Set-ItemProperty -Path $($Base+$Location) -Name $SageSet -Type DWORD -Value 2 -ea silentlycontinue | Out-Null
}

# Do the clean-up. Have to convert the SageSet number
$Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length-4)))"
Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args

# Remove the Stateflags
ForEach($Location in $Locations)
{
    Remove-ItemProperty -Path $($Base+$Location) -Name $SageSet -Force -ea silentlycontinue | Out-Null
}