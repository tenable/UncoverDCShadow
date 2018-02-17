<#
.SYNOPSIS
Dynamically find out if DCShadow is being exploited on a domain
.DESCRIPTION
Execute the module function to dynamically find out if DCShadow is being exploited on a domain
.PARAMETER Server
[Optional] Server to monitor. If not given, will use the current user's logon controller.
.PARAMETER Credential
[Optional] AD account to use to connect. If not given, will implicitly use the current user's credentials.
.EXAMPLE
Trap-DCShadowAttempt

Implicitly use the current user's credentials and domain
.EXAMPLE
Trap-DCShadowAttempt -Server 192.168.1.1

Implicitly use the current user's credentials on the domain controller at 192.168.1.1
.EXAMPLE
Trap-DCShadowAttempt -Server 192.168.1.1 -Credential (Get-Credential -Message "Domain account to use")

Use the explicitly specified credentials on the domain controller at 192.168.1.1
.EXAMPLE
$InformationPreference = $VerbosePreference = $DebugPreference = 'Continue' ; Trap-DCShadowAttempt

Implicitly use the current user's credentials and domain, display all information
.EXAMPLE
$InformationPreference = $VerbosePreference = $DebugPreference = 'Continue' ; Trap-DCShadowAttempt -Server 192.168.56.5 -Credential (New-Object System.Management.Automation.PSCredential ('UnprivilegedUser', (ConvertTo-SecureString "SecurePwd" -AsPlainText -Force)))

Display all available information while using the explicitly-specified credentials on the domain controller at 192.168.1.1
Example Notes:
* A not-secure way to deal with credential is shown in this example; prefer using the Get-Credential cmdlet instead
* This is the opportunity to show that you can use any unprivileged domain user to run this script
.NOTES
# PowerShell streams usage:
- Output: An object for each detected DCShadow attempt
- Information: Just [String] information about the detection state, started and waiting for changes, DCShadow attack found or quitting the application
- Warning: A "potentially suspicious" element has been detected - including legit, newly-promoted DCs, so there's not only fully suspicious elements.
- Verbose: Dump modified AD objects

Multiple suspicious elements detected (Warning stream) on the "same object" lead to confirmation of a DCShadow attack (Output stream).

# Privileges
A simple, unprivileged user account is sufficient to run this, no special domain privilege is required.

# Related
https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [String] $Server = '',

    [Parameter(Mandatory = $false)]
    [PSCredential] $Credential = $null
)

Import-Module -Force (Join-Path -Path $PSScriptRoot -ChildPath 'UncoverDCShadow.psm1') -WarningAction SilentlyContinue -Verbose:$false

Trap-DCShadowAttempt -Server $Server -Credential $Credential
