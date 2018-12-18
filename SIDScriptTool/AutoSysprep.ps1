
# ****************************************************************
# First Release 2016/10/18
# Update on 2018/11/08
# Version 3.0.1
# Support Windows Server 2008, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2016. 
# Required PowerShell Version: 3.0 +
# Make NO guarantee since configuration on the machine varies. Feedback is welcome. Make sure you have backup the machine and data before run this script. 
# Author: Jiasheng
# ****************************************************************

<#
.Synopsis
  This script will sysprep the windows image to regenearte a new SID. 
.DESCRIPTION
    Use this only on Aliyun Windows Images. Support Windows Server 2008, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2016. 
.EXAMPLE
   AutoSysprep.ps1
.EXAMPLE
   AutoSysprep.ps1 -Password <ABCDEF>
.EXAMPLE
    AutoSysprep.ps1 -PostAction "quit"
.EXAMPLE
    AutoSysprep.ps1 -SkipRearm -PostAction "reboot"
#>
Param
(
    [Parameter(Mandatory = $false)]
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRearm,

    [Parameter(Mandatory = $false)]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [string]$Hostname,

    [Parameter(Mandatory = $false)]
    [ValidateSet("shutdown", "reboot", "quit")]
    [string]$PostAction = "shutdown"
)

if ($Help.IsPresent) {
    $help_content = @'
.Synopsis

  This script will sysprep the windows image to regenearte a new SID. 

.Caution

    This script is offered 'as is' with no official support. We Make NO guarantee since configuration varies in real world. Make sure the machine and data are fully backup before run this script.A failed sysprep will destroy the OS.
    Use this only on Aliyun Windows Images. Support Windows Server 2008, Windows Server 2008 R2, Windows Server 2012 R2 and Windows Server 2016. 

.Usage:

Add -SkipRearm switch if you don't want to rearm the system again(reset the activation grace period). Works only for Windows Server 2008 R2 or later OS.

Add -Password string to add the plained password text via command line. If this is ignored(null), a random password string is generated. You may have to change the password from Aliyun ECS console at the next logon.

Add -Hostname string to specify hostname via command line. If this is ignored. A random hostname will be generated.

Add -PostAction <***>: Specify the action after perform sysprep. By default it is "shutdown". You can also use "reboot" or just "quit".

.EXAMPLE
   AutoSysprep.ps1

.EXAMPLE
   AutoSysprep.ps1 -Password <ABCDEFG>

.EXAMPLE
    AutoSysprep.ps1 -PostAction "quit"

.EXAMPLE
    AutoSysprep.ps1 -SkipRearm -PostAction "reboot"
'@
    write-host $help_content -ForegroundColor Green
    return
}

#Predefine the value. 
$OSWMI = Get-WmiObject -Class Win32_OperatingSystem

$isClientOS = $OSWMI.ProductType -eq 1

$is_win7Kernel = $OSWMI.Version.StartsWith("6.1")

$is_2008 = $OSWMI.Version.StartsWith("6.0")

$is_2008_r2 = $is_win7Kernel -and (-not $isClientOS)

# Get Culture from the current system and we will set the InputLocale, SystemLocale, UILanguage,UserLocale based on the Culture.
# On Windows 7, Get-Culture may not accurate if multi languages installed. So, try read regitry key PreferredUILanguages instead.
# If read registry key failed, use Get-Culture instead.
$Languages = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop").PreferredUILanguages
if ($Languages -eq $null) {
    $Language_Name = (Get-Culture).Name
}
else {
    $Language_Name = $Languages[0].Trim()
}

# Get Timezone value. If get failed, use China Standard Time instead.
$Timezone_name = [TimeZoneInfo]::Local.Id
if ($Timezone_name -eq $null) {
    $Timezone_name = "China Standard Time"
}

#Get the system ARCHITECTURE
$os_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE

# A bug in Powershell 5.0 cause sysprep failed. http://blog.buktenica.com/windows-management-framework-breaks-sysprep/
if (($PSVersionTable.PSVersion).tostring().startswith("5.") -and ($is_2008_r2)) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\StreamProvider" -Name LastFullPayloadTime -Value 0 -PropertyType DWord -Force | Out-Null
}

#Change the user Password:
if ([String]::IsNullOrEmpty($Password)) {
    $num = -join ((48..57) | Get-Random -Count 2 | % {[char]$_})
    $lower = -join ((65..90) | Get-Random -Count 3 | % {[char]$_})
    $upper = -join ((97..122) | Get-Random -Count 3 | % {[char]$_})
    $plainpassword = -join ($upper, $lower, $num)
}
else {
    $plainpassword = $Password
}
$EncrypteText = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plainpassword + "AdministratorPassword"))

#Check if rearm is skipped. If user specify skip rearm or the Windows Rearm count -eq 0, we will skip rearm. 
$rearm_ans = ""
$answer_file = ""

# Works on Windows Server 2008 R2 or later answer file. For Windows Server 2008 we force skip rearm.
if (($skiprearm.IsPresent) -or ((Get-WmiObject SoftwareLicensingService).RemainingWindowsReArmCount -eq 0)) {
    $rearm_ans = @"
        <component name="Microsoft-Windows-Security-SPP" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipRearm>1</SkipRearm>
        </component>
"@
}

# If Hostname is not specified, hostname is null and Sysprep will generate a random string.
$computersetting = "<ComputerName>${Hostname}</ComputerName>"

#Generate answer file.
if ($is_2008) {
    $answer_file = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="generalize">
        <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
        </component>
        <component name="Microsoft-Windows-Security-Licensing-SLC" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipRearm>1</SkipRearm>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Description>EnableAdmin</Description>
                    <Order>1</Order>
                    <Path>cmd /c net user Administrator /active:yes</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Path>cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 0 /f</Path>
                    <Order>2</Order>
                    <Description>UnfilterAdministratorToken</Description>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\OOBE /v UnattendCreatedUser /t REG_DWORD /d 1 /f</Path>
                    <Order>3</Order>
                    <Description>disable user account page</Description>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
        <component name="Microsoft-Windows-Security-Licensing-SLC-UX" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OEMInformation>
                <HelpCustomized>false</HelpCustomized>
            </OEMInformation>
            <RegisteredOrganization>Aliyun</RegisteredOrganization>
            <RegisteredOwner />
            <TimeZone>${Timezone_name}</TimeZone>
            ${computersetting}
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>${Language_Name}</InputLocale>
            <SystemLocale>${Language_Name}</SystemLocale>
            <UILanguage>${Language_Name}</UILanguage>
            <UserLocale>${Language_Name}</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>%SystemRoot%\System32\reg.exe ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ /v Start_ShowRun /t REG_DWORD /d 1 /f</CommandLine>
                    <Description>Show Run command in Start Menu</Description>
                    <Order>20</Order>
                </SynchronousCommand>
            </FirstLogonCommands>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <NetworkLocation>Home</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <RegisteredOrganization>Aliyun</RegisteredOrganization>
            <RegisteredOwner />
            <UserAccounts>
                <AdministratorPassword>
                    <Value>${EncrypteText}</Value>
                    <PlainText>false</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="catalog:c:/users/administrator/desktop/install_windows longhorn serverenterprise.clg" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@
}
else {
    $answer_file = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>${Language_Name}</InputLocale>
            <SystemLocale>${Language_Name}</SystemLocale>
            <UILanguage>${Language_Name}</UILanguage>
            <UserLocale>${Language_Name}</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Home</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <RegisteredOrganization>Aliyun</RegisteredOrganization>
            <RegisteredOwner />
            <UserAccounts>
                <AdministratorPassword>
                    <Value>${EncrypteText}</Value>
                    <PlainText>false</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>%SystemRoot%\System32\reg.exe ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ /v Start_ShowRun /t REG_DWORD /d 1 /f</CommandLine>
                    <Order>20</Order>
                    <Description>Show Run command in Start Menu</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
    <settings pass="generalize">
        <component language="neutral" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" versionScope="nonSxS" publicKeyToken="31bf3856ad364e35" processorArchitecture="${os_ARCHITECTURE}" name="Microsoft-Windows-PnpSysprep">
            <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
        </component>
        ${rearm_ans}
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Description>EnableAdmin</Description>
                    <Order>1</Order>
                    <Path>cmd /c net user Administrator /active:yes</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Description>UnfilterAdministratorToken</Description>
                    <Order>2</Order>
                    <Path>cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Description>disable user account page</Description>
                    <Order>3</Order>
                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\OOBE /v UnattendCreatedUser /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
        <component name="Microsoft-Windows-Security-SPP-UX" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="${os_ARCHITECTURE}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OEMInformation>
                <HelpCustomized>false</HelpCustomized>
            </OEMInformation>
            ${computersetting}
            <TimeZone>${Timezone_name}</TimeZone>
            <RegisteredOwner />
            <RegisteredOrganization>Aliyun</RegisteredOrganization>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="catalog:e:/answerfiles/win7/install_windows 7 enterprise.clg" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@
}
Set-Content -Path $env:windir\system32\sysprep\sysprep_ans.xml -Value $answer_file

#Run Sysprep.
& cmd /c ${env:windir}\system32\sysprep\sysprep.exe /generalize /oobe /quit /unattend:${env:windir}\system32\sysprep\sysprep_ans.xml
if ($LASTEXITCODE -ne 0) {
    Write-Error "Sysprep failed with error code ${LASTEXITCODE}"
    return $LASTEXITCODE
}

Remove-Item ${env:windir}\system32\sysprep\sysprep_ans.xml -Force

$TotalControlSet = ((Get-ChildItem "HKLM:\System") | where {$_.PSChildName -Like "*ControlSet*"})
foreach ($i in $TotalControlSet) {
    $ccc = $i.PSChildName
    if (Test-Path "HKLM:\System\${ccc}\Services\xenpci\Parameters") {
        Clear-Itemproperty -Path HKLM:\System\${ccc}\Services\xenpci\Parameters -Name hide_devices -ErrorAction SilentlyContinue
    }
}

if ($PostAction -eq "shutdown") {
    & shutdown -s -f -t 05
}
elseif ($PostAction -eq "reboot") {
    & shutdown -r -f -t 05
}