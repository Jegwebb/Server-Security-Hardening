<#
    :Title: Server Hardening Script

    :Author      : J-G
    :Date        : 16/05/2025
    :Version     : 1.3

    :prerequisite: 

                    - Requires Powershell to be run as Administrator
    
    :Description :  Script to perform server hardening settings on a new on-prem or Azure Windows Servers.

    :Instructions:  
                     
    :Changelog   :  - V1.0 - 10/08/2023 - 
                    - V1.1 - 14/11/2023 - Added Hyper-V check and SPECTRE fix, Added disable SMBv1, Fixed TLS settings, Added disable NTLMv1 Authentication.
                    - V1.2 - 23/10/2024 - Added checks for cipher suites before removal to avoid errors
                    - V1.3 - 16/05/2025 - Added check for LLMNR and if enabled, disable it.
               
#>

# ---------------------------------------------------------------------------------------------
# Configuration


# ---------------------------------------------------------------------------------------------



# Disable TLS 1.0, 1.1, SSL 3.0 SSL 2.0 - Set TLS 1.2

<#
# TLS 1.3

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
#>

# TLS 1.2

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
        
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null


New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
 
# TLS 1.1

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# TLS 1.0

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# SSL 3.0

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# SSL 2.0

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# Enable Server Message Block signing

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name 'EnableSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name 'RequireSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name 'EnableSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name 'RequireSecuritySignature' -Value '1' -PropertyType 'DWord' -Force | Out-Null

# Disable SMBv1

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name 'SMB1' -Value '0' -PropertyType 'DWord' -Force | Out-Null

# Disable NTLMv1 Authentication

New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"  -Name 'lmcompatibilitylevel' -Value '5' -PropertyType 'DWORD' -Force

# Enable user-to-kernel protection along with other protections for CVE 2017-5715 and protections for CVE-2018-3639 (Speculative Store Bypass): SPECTRE

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name 'FeatureSettingsOverride' -Value '72' -PropertyType 'DWord' -Force | Out-Null

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name 'FeatureSettingsOverrideMask' -Value '3' -PropertyType 'DWord' -Force | Out-Null

# For Hyper-V servers

If ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -eq 'Enabled') 
{New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name 'MinVmVersionForCpuBasedMitigations' -Value '1.0' -PropertyType 'String' -Force | Out-Null} 

# WinVerifyTrust Signature Validation CVE-2013-3900 Mitigation (EnableCertPaddingCheck)

If (!(Test-Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"))
{New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null}

New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name 'EnableCertPaddingCheck' -Value '1' -PropertyType 'String' -Force | Out-Null

If (!(Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"))
{New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null}

New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name 'EnableCertPaddingCheck' -Value '1' -PropertyType 'String' -Force | Out-Null

New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name 'EnableCertPaddingCheck' -Value '1' -PropertyType 'String' -Force | Out-Null

# Disable LLMNR if it is enabled - CVE-2011-0657

$LLMNRCHECK = $(Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast).EnableMulticast

If ($LLMNRCHECK -ne "0") 
{
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -Value '0' -PropertyType 'DWORD' -Force | Out-Null
}

# Disable 3DES SHA and RC4 SHA & MD5
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002

$3DES = (Get-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA').Name
$RC4 = (Get-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA').Name
$MD5 = (Get-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5').Name

If ($3DES -ne $Null) {Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'} 
If ($RC4 -ne $Null) {Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'} 
If ($MD5 -ne $Null) {Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5'} 
