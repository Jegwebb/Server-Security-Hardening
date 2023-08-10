<#
    :Title: Server hardening script

        Author      : J-G
        Date        : 10/08/2023
        Version     : 1.0
   
    :Notes
        prerequisite: 

        - Requires Powershell to be run as Administrator
    
    :Description 
                 Script to perform server hardening settings on a new on-prem or azure Windows Servers.

                 Instructions:
                 - Add the domain name in the configre section below.  You will be prompted for your domain admin credentials to join the domain.
         
    :Changelog   : 
                
#>

# ---------------------------------------------------------------------------------------------
# Configuration

$DomainName = ""

# ---------------------------------------------------------------------------------------------

# Change Time Zone, Region & Language settings

Set-TimeZone "GMT Standard Time"

Set-WinSystemLocale en-GB

Set-WinUILanguageOverride -Language en-GB

Update-MpSignature -UpdateSource MicrosoftUpdateServer

# Disable TLS 1.0, 1.1, SSL 3.0 SSL 2.0 - Set TLS 1.2,TLS 1.3 to enabled

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null}
        
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\Enabled"))
    {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
    else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault"))
    {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
    else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null}

    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\Enabled"))
    {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
    else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\DisabledByDefault")) `
    {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
    else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
    
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\DisabledByDefault")) `
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\DisabledByDefault")) `
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"))
{New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null}

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\Enabled"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null}
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\DisabledByDefault"))
{New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}
else {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null}

# Enable Server Message Block signing

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name 'EnableSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name 'RequireSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name 'EnableSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name 'RequireSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# Enable user-to-kernel protection on AMD processors along with other protections for CVE 2017-5715 and protections for CVE-2018-3639 (Speculative Store Bypass): SPECTRE

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name 'FeatureSettingsOverride' -Value '72' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name 'FeatureSettingsOverrideMask' -Value '3' -PropertyType 'DWord' -Force | Out-Null

# WinVerifyTrust Signature Validation CVE-2013-3900 Mitigation (EnableCertPaddingCheck)

If (!(Test-Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"))
{New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null}

New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name 'EnableCertPaddingCheck' -Value '1' -PropertyType 'String' -Force | Out-Null

If (!(Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"))
{New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null}

New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name 'EnableCertPaddingCheck' -Value '1' -PropertyType 'String' -Force | Out-Null


# DIsable 3DES SHA and RC4 SHA & MD5
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002

Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'
Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5'




Add-Computer -domainname $DomainName -Credential (Get-Credential)
