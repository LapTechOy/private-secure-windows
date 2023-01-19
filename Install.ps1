
<#

.DESCRIPTION
Applies a Windows privacy and security configuration baseline to local group policy + Defender Hardening.

Execute this script with one of these options to install the corresponding baseline:
 -Level Basic             - [default] Basic security and privacy
 -Level HighSecurity      - High security settings (assumes basic security setting are in place)
Advanced use and more granular control: 
 -Level BasicSecurity         - Basic security, with no privacy settings added
 -Level BasicPrivacy          - Basic privacy, with no security settings added

#>

[CmdletBinding()]
param(
    [ValidateSet("Basic","BasicSecurity","BasicPrivacy","HighSecurity","HighSecurityCredGuard", `
        "HighSecurityComputer","HighSecurityDomain","HighSecurityBitlocker","ExtremePrivacy")]
    [string]$Level,
    [string]$LgpoPath = ".\Tools"
)

function Warn([string]$Msg){
    $Resp = $Host.UI.PromptForChoice("Warning",$Msg,@("&Yes","&No"),1)
    if ($Resp -eq 1){
        exit
    } 
}

# Check if supported Windows build
# Windows 11 22H2 - 22621
# Windows 11 21H2 - 22000
# Windows 10 22H2 - 19045
# Windows 10 21H2 - 19044
# Windows 10 21H1 - 19043
$OSVersion = [environment]::OSVersion
if (-not $OSVersion.Version.Build -in @(19043,19044,19045,22000,22621)){
    $Msg = "Unsupported version of Windows detected. Some settings might not work as intended. " `
    + "Do you want to continue?"
    Warn $Msg
}

$IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (-not $IsAdmin){
    throw "Script is not running with administrative privileges. Failed to apply policies"
}

if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2){
    throw "Execution of this local-policy script is not supported on domain controllers. Exiting."
}

if (-not $Level){
    $Msg = "Selecting default level: Basic`r`n" `
    + "This will apply basic privacy and security settings. " `
    + "Do you want to continue?"
    Warn $Msg
    $Level = "Basic"
}


############# Start copied code from Microsoft Windows Security Baseline #############

# Get location of this script
$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

# Verify availability of LGPO.exe; if not in path, but in Tools subdirectory, add Tools subdirectory to the path.
$origPath = ""
if ($null -eq (Get-Command LGPO.exe -ErrorAction Ignore)){
    if (Test-Path -Path $rootDir\Tools\LGPO.exe)    {
        $origPath = $env:Path
        $env:Path = "$rootDir\Tools;" + $origPath
        Write-Verbose $env:Path
        Write-Verbose (Get-Command LGPO.exe)
    } else {
$lgpoErr = @"

  ============================================================================================
    LGPO.exe must be in the Tools subdirectory or somewhere in the Path. LGPO.exe is part of
    the Security Compliance Toolkit and can be downloaded from this URL:
    https://www.microsoft.com/download/details.aspx?id=55319
  ============================================================================================
"@
        Write-Error $lgpoErr
        return
    }
}

# All log output in Unicode
$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

Push-Location $rootDir

# Log file full path
$logfile = [System.IO.Path]::Combine($rootDir, "PrivateSecureWindows-" + [datetime]::Now.ToString("yyyyMMdd-HHmm-ss") + ".log")
Write-Host "Logging to $logfile ..." -ForegroundColor Cyan
$MyInvocation.MyCommand.Name + ", " + [datetime]::Now.ToString() | Out-File -LiteralPath $logfile

# Functions to simplify logging and reporting progress to the display
$dline = "=================================================================================================="
$sline = "--------------------------------------------------------------------------------------------------"
function Log([string] $line){
    $line | Out-File -LiteralPath $logfile -Append
}
function LogA([string[]] $lines){
    $lines | foreach { Log $_ }
}
function ShowProgress([string] $line){
    Write-Host $line -ForegroundColor Cyan
}
function ShowProgressA([string[]] $lines){
    $lines | foreach { ShowProgress $_ }
}
function LogAndShowProgress([string] $line){
    Log $line
    ShowProgress $line
}
function LogAndShowProgressA([string[]] $lines){
    $lines | foreach { LogAndShowProgress $_ }
}
# Wrapper to run LGPO.exe so that both stdout and stderr are redirected and
# PowerShell doesn't complain about content going to stderr.
function RunLGPO([string] $lgpoParams){
    ShowProgress "Running LGPO.exe $lgpoParams"
    LogA (cmd.exe /c "LGPO.exe $lgpoParams 2>&1")
}

############# End copied code from Microsoft Windows Security Baseline ################
Log $dline

$BasicPrivacy = ".\GPOs\BasicPrivacy\Version 21H2_Win10\Enterprise\GPO"
$BasicSecBitlocker = ".\GPOs\BasicSecBitlocker\{283903C7-6FA6-4078-92A2-25C026324F68}\DomainSysvol\GPO"
$BasicSecComputer = ".\GPOs\BasicSecComputer\{70CF3C23-9F4D-4E50-8D2A-DEAD79D5A724}\DomainSysvol\GPO"
$BasicSecDefender = ".\GPOs\BasicSecDefender\{72D1AD12-B481-44E3-9529-AC7C658508B2}\DomainSysvol\GPO"
$BasicSecDomain = ".\GPOs\BasicSecDomain\{14144BB4-26AC-4A90-B4E1-BE99F58A4FFF}\DomainSysvol\GPO"
$BasicSecUser = ".\GPOs\BasicSecUser\{065B86DC-5229-4FC1-A8C2-BF989FDAEEB4}\DomainSysvol\GPO"
$HighSecBitlocker = ".\GPOs\HighSecBitlocker\{98ECD203-A3B2-4419-B1F0-E5A68F4044CB}\DomainSysvol\GPO"
$HighSecComputer = ".\GPOs\HighSecComputer\{FB5B4EEE-3202-4D88-B70D-B0EDE21699D3}\DomainSysvol\GPO"
$HighSecCredGuard = ".\GPOs\HighSecCredGuard\{1C44F912-2A2E-444E-81E9-005FDB9018FC}\DomainSysvol\GPO"
$HighSecDomain = ".\GPOs\HighSecDomain\{0CC6A02E-2EFE-4774-B3C7-209B1C102367}\DomainSysvol\GPO"
$ExtremePrivacy = ".\GPOs\ExtremePrivacy\Version 21H2_Win10\Enterprise\GPO"

# Extra settings for other versions of Windows
$DeltaW11_21H2BasicPrivacy =  ".\GPOs\Deltas\W11_21H2\BasicPrivacy.txt"
$DeltaW11_21H2BasicSecurity = ".\GPOs\Deltas\W11_21H2\BasicSecurity.txt"

$DeltaW11_22H2BasicSecComputer = ".\GPOs\Deltas\W11_22H2\BasicSecComputer.txt"
$DeltaW11_22H2BasicSecDomain =   ".\GPOs\Deltas\W11_22H2\BasicSecDomain\GptTmpl.inf"
$DeltaW11_22H2HighSecComputer =  ".\GPOs\Deltas\W11_22H2\HighSecComputer.txt"
$DeltaW11_22H2HighSecCredGuard = ".\GPOs\Deltas\W11_22H2\HighSecCredGuard.txt"

$DeltaW10_22H2BasicSecDomain =   ".\GPOs\Deltas\W10_22H2\BasicSecDomain\GptTmpl.inf"
$DeltaW10_22H2BasicSecComputer = ".\GPOs\Deltas\W10_22H2\BasicSecComputer.txt"
$DeltaW10_22H2HighSecComputer =  ".\GPOs\Deltas\W10_22H2\HighSecComputer.txt"

# Determine which GPOs to import
$GPOs = @()
$Deltas = @()

if ($Level -in @("Basic","BasicSecurity")){
    $GPOs += $BasicSecBitlocker
    $GPOs += $BasicSecComputer
    $GPOs += $BasicSecDefender
    $GPOs += $BasicSecDomain
    $GPOs += $BasicSecUser

    if ($OSVersion.Version.Build -in @(22000,22621)){
        $Deltas += $DeltaW11_21H2BasicSecurity
    }
	
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2BasicSecComputer
		$AddW11_22H2BasicSecDomain = $true
    }

	if ($OSVersion.Version.Build -eq 19045){
        $Deltas += $DeltaW10_22H2BasicSecComputer
		$AddW10_22H2BasicSecDomain = $true
    }    

    # Warn against self-lockout if user is connected remotely on a public network
    if ("Public" -in (Get-NetConnectionProfile).NetworkCategory){
        $Msg = 'You are on a "Public" network profile and are about to apply settings that ' `
        + 'closes all inbound network connections. If you are remotely connected, you might ' `
        + 'lose access. Consider changing the network to "Private" profile before proceeding. ' `
        + 'Do you want to continue?'
        Warn $Msg
    }
} 

if ($Level -in @("HighSecurity")){
    $GPOs += $HighSecBitlocker
    $GPOs += $HighSecComputer
    $GPOs += $HighSecCredGuard
    $GPOs += $HighSecDomain
	
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2HighSecComputer
		$Deltas += $DeltaW11_22H2HighSecCredGuard
    }

    if ($OSVersion.Version.Build -eq 19045){
        $Deltas += $DeltaW10_22H2HighSecComputer
    }
}

if ($Level -in @("HighSecurityBitlocker")){ $GPOs += $HighSecBitlocker }
if ($Level -in @("HighSecurityDomain"))   { $GPOs += $HighSecDomain }
if ($Level -in @("HighSecurityComputer")) { 
	$GPOs += $HighSecComputer 
	if ($OSVersion.Version.Build -eq 22621){
        $Deltas += $DeltaW11_22H2HighSecComputer
    }
    if ($OSVersion.Version.Build -eq 19045){
        $Deltas += $DeltaW10_22H2HighSecComputer
    }
}
if ($Level -in @("HighSecurityCredGuard")){ 
	$GPOs += $HighSecCredGuard 
	if ($OSVersion.Version.Build -eq 22621){
		$Deltas += $DeltaW11_22H2HighSecCredGuard
    }
}


if ($Level -in @("Basic","BasicPrivacy")){
    $GPOs += $BasicPrivacy

    if ($OSVersion.Version.Build -in @(22000,22621)){
        $Deltas += $DeltaW11_21H2BasicPrivacy
    }

    LogAndShowProgress "Removing preinstalled apps"
    # This cannot be done with GPO/Registry, but is a part of the restricted traffic baseline:
    # https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#17-preinstalled-apps
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingNews"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage *.Twitter | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
    Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
    Log $dline
}

LogAndShowProgress "Copying Custom Administrative Templates"
# todo: use templates for Windows 11 22H2 on newer systems
Copy-Item -Force -Path .\Templates\*.admx -Destination "$Env:Systemroot\PolicyDefinitions"
Copy-Item -Force -Path .\Templates\en-US\*.adml -Destination "$Env:Systemroot\PolicyDefinitions\en-US"
Log $dline

LogAndShowProgress "Configuring Client Side Extensions"
RunLGPO "/v /e mitigation /e audit /e zone /e DGVBS /e DGCI" 
Log $dline

if ($Level -in @("Basic","High","BasicSecurityOnly","BasicSecurityComputerOnly")){
    LogAndShowProgress "Disabling Xbox scheduled task" $Logfile
    LogA (SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /DISABLE)
    Log $dline
}

foreach ($g in $GPOs){
    LogAndShowProgress "Applying GPO: $g"
    RunLGPO "/v /g `"$g`""
    Log $dline
}

foreach ($d in $Deltas){
    LogAndShowProgress "Applying GPO: $d"
    RunLGPO "/v /t `"$d`""
    Log $dline
}

if ($AddW11_22H2BasicSecDomain){
    LogAndShowProgress "Applying GPO: $DeltaW11_22H2BasicSecDomain"
	RunLGPO "/v /s `"$DeltaW11_22H2BasicSecDomain`""
	Log $dline
}

if ($AddW10_22H2BasicSecDomain){
    LogAndShowProgress "Applying GPO: $DeltaW10_22H2BasicSecDomain"
	RunLGPO "/v /s `"$DeltaW10_22H2BasicSecDomain`""
	Log $dline
}

# Experimental / untested
if ($Level -eq "ExtremePrivacy"){

    $Msg = 'You are about to implement privacy settings that reduces security and usability. ' `
    + 'Please review the machine.txt and GptTmpl.inf files, and only continue if you know what you are doing. ' `
    + 'Do you want to continue?'
    Warn $Msg

    LogAndShowProgress "Applying extreme privacy GPO's"
    RunLGPO "/v /t `"$ExtremePrivacy\Machine\machine.txt`""
    RunLGPO "/v /s `"$ExtremePrivacy\Machine\GptTmpl.inf`""
    RunLGPO "/v /t `"$ExtremePrivacy\User\user.txt`""
    Log $dline
}

# Restore original path if modified
if ($origPath.Length -gt 0)
{
    $env:Path = $origPath
}
# Restore original output encoding
$OutputEncoding = $OutputEncodingPrevious

# Restore original directory location
Pop-Location

LogAndShowProgress "Done. Please reboot your device to apply all settings"


$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

Write-Host "Enabling Windows Defender Protections and Features" -ForegroundColor Green -BackgroundColor Black

Write-Host "Copying Files to Supported Directories"
#Windows Defender Configuration Files
mkdir "C:\temp\Windows Defender"; Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination C:\temp\"Windows Defender"\ -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Enabling Windows Defender Exploit Protections..."
#Enable Windows Defender Exploit Protection
Set-ProcessMitigation -PolicyFilePath "C:\temp\Windows Defender\DOD_EP_V3.xml"

$PolicyPath = "C:\temp\Windows Defender\CIP\WDAC_V1_Recommended_Audit\*.cip"
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
ForEach ($Policy in (Get-ChildItem -Recurse $PolicyPath).Fullname) {
  $PolicyBinary = "$Policy"
  $DestinationFolder = $env:windir+"\System32\CodeIntegrity\CIPolicies\Active\"
  $RefreshPolicyTool = "./Files/EXECUTABLES/RefreshPolicy(AMD64).exe"
  Copy-Item -Path $PolicyBinary -Destination $DestinationFolder -Force
  & $RefreshPolicyTool
}

Write-Host "Enabling Windows Defender Features..."
#https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
#https://social.technet.microsoft.com/wiki/contents/articles/52251.manage-windows-defender-using-powershell.aspx
#https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
#Enable real-time monitoring
Write-Host " -Enabling real-time monitoring"
Set-MpPreference -DisableRealtimeMonitoring $false
#Enable cloud-deliveredprotection
Write-Host " -Enabling cloud-deliveredprotection"
Set-MpPreference -MAPSReporting Advanced
#Enable sample submission
Write-Host " -Enabling sample submission"
Set-MpPreference -SubmitSamplesConsent Always
#Enable checking signatures before scanning
Write-Host " -Enabling checking signatures before scanning"
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
#Enable behavior monitoring
Write-Host " -Enabling behavior monitoring"
Set-MpPreference -DisableBehaviorMonitoring $false
#Enable IOAV protection
Write-Host " -Enabling IOAV protection"
Set-MpPreference -DisableIOAVProtection $false
#Enable script scanning
Write-Host " -Enabling script scanning"
Set-MpPreference -DisableScriptScanning $false
#Enable removable drive scanning
Write-Host " -Enabling removable drive scanning"
Set-MpPreference -DisableRemovableDriveScanning $false
#Enable Block at first sight
Write-Host " -Enabling Block at first sight"
Set-MpPreference -DisableBlockAtFirstSeen $false
#Enable potentially unwanted apps
Write-Host " -Enabling potentially unwanted apps"
Set-MpPreference -PUAProtection 1
#Enable archive scanning
Write-Host " -Enabling archive scanning"
Set-MpPreference -DisableArchiveScanning $false
#Enable email scanning
Write-Host " -Enabling email scanning"
Set-MpPreference -DisableEmailScanning $false
#Enable File Hash Computation
Write-Host " -Enabling File Hash Computation"
Set-MpPreference -EnableFileHashComputation $true
#Enable Intrusion Prevention System
Write-Host " -Enabling Intrusion Prevention System"
Set-MpPreference -DisableIntrusionPreventionSystem $false
#Enable SSH Parcing
Write-Host " -Enabling SSH Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable TLS Parcing
Write-Host " -Enabling TLS Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable SSH Parcing
Write-Host " -Enabling SSH Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable DNS Parcing
Write-Host " -Enabling DNS Parsing"
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
#Enable DNS Sinkhole 
Write-Host " -Enabling DNS Sinkhole"
Set-MpPreference -EnableDnsSinkhole $true
#Enable Controlled Folder Access and setting to block mode
Write-Host " -Enabling Controlled Folder Access and setting to block mode"
Set-MpPreference -EnableControlledFolderAccess Enabled
#Enable Network Protection and setting to block mode
Write-Host " -Enabling Network Protection and setting to block mode"
Set-MpPreference -EnableNetworkProtection Enabled
#Enable Sandboxing for Windows Defender
Write-Host " -Enabling Sandboxing for Windows Defender"
setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null
#Set cloud block level to 'High'
Write-Host " -Setting cloud block level to 'High'"
Set-MpPreference -CloudBlockLevel High
#Set cloud block timeout to 1 minute
Write-Host " -Setting cloud block timeout to 1 minute"
Set-MpPreference -CloudExtendedTimeout 50
#Schedule signature updates every 8 hours
Write-Host " -Scheduling signature updates every 8 hours"
Set-MpPreference -SignatureUpdateInterval 8
#Randomize Scheduled Task Times
Write-Host " -Randomizing Scheduled Task Times"
Set-MpPreference -RandomizeScheduleTaskTimes $true

Write-Host "Disabling Account Prompts"
# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
If (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State\AccountProtection_MicrosoftAccount_Disconnected")) {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType "DWORD" -Value "1" -Force
}Else {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType "DWORD" -Value "1" -Force
}

Write-Host "Enabling Cloud-delivered Protections"
#Enable Cloud-delivered Protections
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Write-Host "Enabling... Windows Defender Attack Surface Reduction Rules"
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
Write-Host " -Block executable content from email client and webmail"
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block all Office applications from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office applications from creating executable content"
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office applications from injecting code into other processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block JavaScript or VBScript from launching downloaded executable content"
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block execution of potentially obfuscated scripts"
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Win32 API calls from Office macros"
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block credential stealing from the Windows local security authority subsystem"
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block persistence through WMI event subscription"
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block process creations originating from PSExec and WMI commands"
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block untrusted and unsigned processes that run from USB"
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office communication application from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Adobe Reader from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block persistence through WMI event subscription"
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block abuse of exploited vulnerable signed drivers"
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Use advanced protection against ransomware"
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled

Write-Host "Enabling... Windows Defender Group Policy Settings"
.\Files\LGPO\LGPO.exe /g .\Files\GPO\

Write-Host "Updating Signatures..."
#Update Signatures
# cd $env:programfiles"\Windows Defender"
# .\MpCmdRun.exe -removedefinitions -dynamicsignatures
# .\MpCmdRun.exe -SignatureUpdate
Update-MpSignature -UpdateSource MicrosoftUpdateServer
Update-MpSignature -UpdateSource MMPC

Write-Host "Printting Current Windows Defender Configuration"
# Print Historic Detections
Get-MpComputerStatus ; Get-MpPreference ; Get-MpThreat ; Get-MpThreatDetection


