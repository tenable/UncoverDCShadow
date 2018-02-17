<#
.SYNOPSIS
Dynamically detect DCShadow attempts
.DESCRIPTION
Main function: Trap-DCShadowAttempt
#>

## Configuration variables
# Minimum time between creation and deletion of a server or ntdsdsa object for considering this isn't a DCShadow attack (in minutes). Should be more than the time to replicate data.
$g_ConfTimeSpanForCreationDeletion = 60

## Module variables
# Cache for the root DSE Ldap object
$g_rootDSE = $null
# Reasons for flagging DCShadow detection
$g_FlagReasons = @{
    NTDSDSA = "The nTDSDSA object hasn't been found"
    DomainNC = "The nTDSDSA object isn't referenced in the root domain object"
    NTDSConnection = "The nTDSConnection associated to the nTDSDSA object hasn't been found"
}

## Load necessary assemblies
$null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
$null = [System.Reflection.Assembly]::LoadWithPartialName("System.Net")


Function New-AsyncCallback {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $Callback,

        [Parameter(Mandatory = $true)]
        [PSCustomObject] $Infos
    ) 
    
    Write-Debug "[$(Get-Date)][New-AsyncCallback] Begin"

    If (-not ("AsyncCallbackForPS" -as [type])) {
        Add-Type @"
            using System;
             
            public sealed class AsyncCallbackForPS
            {
                public event AsyncCallback CallbackComplete = delegate { };
                public Object CallbackArgs;
 
                public AsyncCallbackForPS() {}
 
                private void CallbackInternal(IAsyncResult result)
                {
                    CallbackComplete(result);
                }
 
                public AsyncCallback Callback
                {
                    get { return new AsyncCallback(CallbackInternal); }
                }
            }
"@
    }
    $AsyncCB = New-Object AsyncCallbackForPS
    $AsyncCB.CallbackArgs = $Infos
    $null = Register-ObjectEvent -InputObject $AsyncCB -EventName CallbackComplete -Action $Callback
    $AsyncCB.Callback

    Write-Debug "[$(Get-Date)][New-AsyncCallback] End"
}

Function New-DCShadowDetected
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [Hashtable] $Server,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [Hashtable] $Computer,

        [Parameter(Mandatory = $true)]
        [String[]] $SuspiciousReasons
    )

    Write-Debug "[$(Get-Date)][New-DCShadowDetected] Begin"
    Write-Output ([PSCustomObject]@{
        Type = 'DCShadowDetected'
        ServerObject = $Server
        #Computer = $Computer
        Reasons = $SuspiciousReasons
    })
    Write-Debug "[$(Get-Date)][New-DCShadowDetected] End"
}

Function Test-ServerDCShadow
{
    param(
        [Parameter(Mandatory = $true)]
        [String] $Dn,

        [Parameter(Mandatory = $true)]
        [PSCustomObject] $Infos
    )

    Write-Debug "[$(Get-Date)][Test-ServerDCShadow] Begin"

    $Server = $Infos.DCNeedingProof['server'][$Dn]['Server']
    $Flags = $Infos.DCNeedingProof['server'][$Dn]['Flags']
    $suspiciousReasons = @()
    ForEach ($flag in $Flags.Keys) {
        If (-not $Flags[$flag]) {
            $suspiciousReasons += $g_FlagReasons[$flag]
        }
    }

    $serverRefInDcOu = $Server.ServerReference.EndsWith($Infos.DomainControllersOU)
    $sufficientCreationChangeTimeSpan = $Server.WhenCreated.AddMinutes($g_ConfTimeSpanForCreationDeletion) -lt $Server.LastWhenChanged
    $usnCreationChangedDifferent = $Server.UsnCreated -ne $Server.LastUsnChanged

    If ($Server['IsDeleted']) {
        # A server not referenced in the domain controllers is now deleted
        $suspiciousReasons += "Server object deleted early on"

        If (-not $serverRefInDcOu) {
            $suspiciousReasons += "Server referenced by the deleted object not in the Domain Controllers OU: $($Server.ServerReference)"
        }

        If (-not $sufficientCreationChangeTimeSpan) {
            $suspiciousReasons += "Last registered change happens near creation"
        }

        If (-not $usnCreationChangedDifferent) {
            $suspiciousReasons += "Created and changed USNs are the same on this deleted object"
        }

        Write-Warning "[$(Get-Date)][Test-ServerDCShadow]  Found following suspicious elements:`n $($suspiciousReasons -join "`n ")"
        Write-Output (New-DCShadowDetected -Server $Server -Computer $null -SuspiciousReasons $suspiciousReasons)
        Write-Output ([PSCustomObject]@{
            Type = 'NeedClean'
            ServerDn = $Dn
        })
    } ElseIf ($suspiciousReasons.Count -eq 0 -and $serverRefInDcOu -and $sufficientCreationChangeTimeSpan -and $usnCreationChangedDifferent) {
        # This server is now considered legit, move it to the registered domain controllers

        $Infos.DomainControllers[$Dn] = @{
            distinguishedname   = $Dn
            objectclass         = @('server')
            whencreated         = $Server.WhenCreated
            usncreated          = $Server.UsnCreated
            whenchanged         = $Server.LastWhenChanged
            usnchanged          = $Server.LastUsnChanged
            serverreference     = $Server.ServerReference
        }

        $ntdsdsaDn = $Server['NTDSDSA']['Dn']
        If ($ntdsdsaDn -and $Infos.DCNeedingProof['ntdsdsa'].ContainsKey($ntdsdsaDn)) {
            $Infos.DCNeedingProof['ntdsdsa'].Remove($ntdsdsaDn)
        }

        Write-Output ([PSCustomObject]@{
            Type = 'NeedClean'
            ServerDn = $Dn
        })
    }
    Write-Debug "[$(Get-Date)][Test-ServerDCShadow] End"
}

Function Write-Entry
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.SearchResultEntry] $Entry
    )

    Write-Debug "[$(Get-Date)][Write-Entry] Begin"

    # Log every change in the Verbose channel
    # As this slows things down, do it only if the Verbose channel isn't silent
    If ($VerbosePreference -ne 'SilentlyContinue') {
        Write-Verbose $Entry.DistinguishedName
        ForEach ($attrName in $Entry.Attributes.AttributeNames) {
            Switch ($attrName) {
                { $_ -in "objectguid", "invocationid" } {
                    $item = (New-Object Guid $Entry.Attributes[$attrName].GetValues([byte[]])).Guid
                    Write-Verbose "`t$($attrName): $item"
                }
                "objectsid" {
                    $item = (New-Object System.Security.Principal.SecurityIdentifier $Entry.Attributes[$attrName].GetValues([byte[]])[0], 0).Value
                    Write-Verbose "`t$($attrName): $item"
                }
                default {
                    ForEach ($item in $Entry.Attributes[$attrName].GetValues([string])) {
                        Write-Verbose "`t$($attrName): $item"
                    }
                }
            }
        }
    }

    Write-Debug "[$(Get-Date)][Write-Entry] End"
}
Export-ModuleMember -Function Write-Entry

Function Confirm-ServerFlag
{
    param(
        [PSCustomObject] $Infos,
        [String] $Dn,
        [String] $Flag
    )

    Write-Debug "[$(Get-Date)][Confirm-ServerFlag] Begin"
    If ($Infos.DCNeedingProof['server'].ContainsKey($Dn)) {
        Write-Debug "[$(Get-Date)][Confirm-ServerFlag]  Setting flag $Flag for server $Dn"
        $Infos.DCNeedingProof['server'][$Dn]['Flags'][$Flag] = $true
    }
    Write-Debug "[$(Get-Date)][Confirm-ServerFlag] End"
}
Export-ModuleMember -Function Confirm-ServerFlag

Function Register-ServerObject
{
    param(
        [PSCustomObject] $Infos,
        [String] $Dn,
        [String] $WhenCreated,
        [String] $UsnCreated,
        [AllowNull()]
        [String] $ServerReferenced,
        [String] $WhenChanged,
        [String] $UsnChanged,
        [Bool] $IsDeleted
    )

    Write-Debug "[$(Get-Date)][Register-ServerObject] Begin"
    $Infos.DCNeedingProof['server'][$Dn] = @{
        Server = @{
            DistinguishedName = $Dn
            Present = $true
            WhenCreated = [DateTime]::ParseExact($WhenCreated, "yyyyMMddHHmmss.f'Z'", $null)
            WhenDeleted = $null
            UsnCreated = $UsnCreated
            UsnDeleted = $null
            IsDeleted = $IsDeleted
            ServerReference = $ServerReferenced
            LastWhenChanged = [DateTime]::ParseExact($WhenChanged, "yyyyMMddHHmmss.f'Z'", $null)
            LastUsnChanged = $UsnChanged
        }
        NTDSDSA = $null
        Flags = @{
            NTDSDSA = $false
            DomainNC = $false
            NTDSConnection = $false
        }
    }
    Write-Debug "[$(Get-Date)][Register-ServerObject] End"
}
Export-ModuleMember -Function Register-ServerObject

Function Update-ADChanges
{
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $Infos,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.SearchResultEntry] $Entry
    )

    Write-Debug "[$(Get-Date)][Update-ADChanges] Begin"
    Write-Entry $Entry

    $dn = $Entry.DistinguishedName

    If ($dn.EndsWith($Infos.SitesCN)) {
        $objectClass = $Entry.Attributes['objectclass'].GetValues([String])
        $whenCreated = $Entry.Attributes['whencreated'].GetValues([String])[0]
        $whenChanged = $Entry.Attributes['whenchanged'].GetValues([String])[0]
        $usnCreated = $Entry.Attributes['usncreated'].GetValues([String])[0]
        $usnChanged = $Entry.Attributes['usnchanged'].GetValues([String])[0]

        If ($objectclass -contains 'server') {
            If ($Entry.Attributes.AttributeNames -contains 'serverreference') {
                $serverReferenced = ($Entry.Attributes['serverreference'].GetValues([String]))[0]
            } Else {
                $serverReferenced = $null
            }

            If ($Entry.Attributes.AttributeNames -contains 'isdeleted') {
                $originalDn = $dn -replace '\\0ADEL:[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}'

                If ($Infos.DCNeedingProof['server'].ContainsKey($originalDn)) {
                    $Infos.DCNeedingProof['server'][$originalDn]['Server']['IsDeleted'] = $true
                    $Infos.DCNeedingProof['server'][$originalDn]['Server']['WhenDeleted'] = [DateTime]::ParseExact($whenChanged, "yyyyMMddHHmmss.f'Z'", $null)
                    $Infos.DCNeedingProof['server'][$originalDn]['Server']['UsnDeleted'] = $usnChanged
                    If ($serverReferenced) {
                        $Infos.DCNeedingProof['server'][$originalDn]['Server']['ServerReference'] = $serverReferenced
                    }
                } Else {
                    Register-ServerObject $Infos $originalDn $whenCreated $usnCreated $serverReferenced $whenChanged $usnChanged $true
                }

                Write-Warning "Server object deletion: $dn"
            } ElseIf (-not $Infos.domainControllers.ContainsKey($dn)) {
                # New domain controller being promoted!
                # ... or maybe a DCShadow attempt

                If ($Infos.DCNeedingProof['server'].ContainsKey($dn)) {
                    $Infos.DCNeedingProof['server'][$dn]['Server']['LastWhenChanged'] = [DateTime]::ParseExact($whenChanged, "yyyyMMddHHmmss.f'Z'", $null)
                    $Infos.DCNeedingProof['server'][$dn]['Server']['LastUsnChanged'] = $usnChanged
                    If ($serverReferenced) {
                        $Infos.DCNeedingProof['server'][$dn]['Server']['ServerReference'] = $serverReferenced
                    }
                } Else {
                    Register-ServerObject $Infos $dn $whenCreated $usnCreated $serverReferenced $whenChanged $usnChanged $false
                    Write-Warning "Server object creation: $dn"
                }
            }
        } ElseIf ($objectclass -contains 'nTDSDSA') {
            $associatedServerDn = $dn.Substring($dn.IndexOf(',') + 1) -replace '\\0ADEL:[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}'

            If ($Entry.Attributes.AttributeNames -contains 'isdeleted' -and $Infos.DCNeedingProof['server'].ContainsKey($associatedServerDn)) {
                $Infos.DCNeedingProof['server'][$associatedServerDn]['NTDSDSA']['IsDeleted'] = $true
                $Infos.DCNeedingProof['server'][$associatedServerDn]['NTDSDSA']['WhenDeleted'] = [DateTime]::ParseExact($whenChanged, "yyyyMMddHHmmss.f'Z'", $null)
                $Infos.DCNeedingProof['server'][$associatedServerDn]['NTDSDSA']['UsnDeleted'] = $usnChanged

                Write-Warning "NTDSDSA object deletion: $dn"
            } ElseIf ($Infos.DCNeedingProof['server'].ContainsKey($associatedServerDn) -and $whenCreated -eq $whenChanged) {
                Confirm-ServerFlag $Infos $associatedServerDn NTDSDSA
                
                $Infos.DCNeedingProof['server'][$associatedServerDn]['NTDSDSA'] = @{
                    Dn = $dn
                    ObjectGuid = $Entry.Attributes['objectguid'].GetValues([String])[0]
                    WhenCreated = [DateTime]::ParseExact($whenCreated, "yyyyMMddHHmmss.f'Z'", $null)
                    WhenDeleted = $null
                    UsnCreated = $usnCreated
                    UsnDeleted = $null
                    IsDeleted = $false
                }
                $Infos.DCNeedingProof['ntdsdsa'][$dn] = @{
                    AssociatedServerDn = $associatedServerDn
                }

                Write-Warning "NTDSDSA object creation: $dn"
            }
        } ElseIf ($objectclass -contains 'nTDSConnection' -and $whenCreated -eq $whenChanged) {
            $associatedNTDSDSADn = $dn.Substring($dn.IndexOf(',') + 1)
            $associatedServerDn = $associatedNTDSDSADn.Substring($associatedNTDSDSADn.IndexOf(',') + 1)
            Confirm-ServerFlag $Infos $associatedServerDn NTDSConnection
        }
    } ElseIf ($dn -eq $Infos.DefaultNC) {
        $objectClass = $Entry.Attributes['objectclass'].GetValues([String])
        $whenCreated = $Entry.Attributes['whencreated'].GetValues([String])[0]
        $whenChanged = $Entry.Attributes['whenchanged'].GetValues([String])[0]
        $usnCreated = $Entry.Attributes['usncreated'].GetValues([String])[0]
        $usnChanged = $Entry.Attributes['usnchanged'].GetValues([String])[0]
        $masteredBy = $Entry.Attributes['masteredby'].GetValues([String])
        ForEach ($master in $masteredBy) {
            If ($Infos.DCNeedingProof['ntdsdsa'].ContainsKey($master)) {
                $associatedServerDn = $Infos.DCNeedingProof['ntdsdsa'][$master]['AssociatedServerDn']
                Confirm-ServerFlag $Infos $associatedServerDn DomainNC
                break
            }
        }
    }

    Write-Debug "[$(Get-Date)][Update-ADChanges] End"
}
Export-ModuleMember -Function Update-ADChanges

Function Invoke-NotifyCallback
{
    param([System.IAsyncResult] $result)

    Write-Debug "[$(Get-Date)][Invoke-NotifyCallback] Begin"

    Try {
        # Re-import the module in this runspace
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'UncoverDCShadow.psm1') -WarningAction SilentlyContinue -Verbose:$false

        $Infos = $Sender.CallbackArgs

        $prc = $Infos.LdapConnection.GetPartialResults($result)

        ForEach ($entry in $prc) {
            $DCShadowDetected = Update-ADChanges $Infos $entry
            If ($DCShadowDetected) {
                Write-Information "Found a DCShadow attack!"
                Write-Output $DCShadowDetected
            }
        }
    } Catch {
        Write-Host $_
    }

    Write-Debug "[$(Get-Date)][Invoke-NotifyCallback] End"
}

Function Register-LdapSearch
{
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $Infos,
        [Parameter(Mandatory = $true)]
        [string] $SearchDn,
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.SearchScope] $Scope
    )

    Write-Debug "[$(Get-Date)][Register-LdapSearch] Begin"

    $Ldap = $Infos.LdapConnection

    [System.DirectoryServices.Protocols.SearchRequest] $request = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList @(
        $SearchDn, # root the search here
        "(objectClass=*)", # very inclusive
        $Scope, # any scope works
        $null # we are interested in all attributes
    )

    $null = $request.Controls.Add((New-Object System.DirectoryServices.Protocols.DirectoryNotificationControl))

    [System.IAsyncResult] $result = $Ldap.BeginSendRequest(
        $request,
        (New-TimeSpan -Days 1),
        [System.DirectoryServices.Protocols.PartialResultProcessing]::ReturnPartialResultsAndNotifyCallback,
        (New-AsyncCallback ${function:Invoke-NotifyCallback} $Infos),
        $request
    )

    Write-Debug "[$(Get-Date)][Register-LdapSearch] End"

    return $result
}

Function Dispose-LdapSearches
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection] $Ldap,
        [Parameter(Mandatory = $true)]
        [System.IAsyncResult[]] $SearchResults
    )

    Write-Debug "[$(Get-Date)][Dispose-LdapSearches] Begin"

    ForEach ($result in $SearchResults)
    {
        # End each async search
        Try {
            $Ldap.Abort($result)
        } Catch {
            Write-Host $_
        }
    }

    $Ldap.Dispose()

    Write-Debug "[$(Get-Date)][Dispose-LdapSearches] End"
}

Function Get-RootDse
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection] $Ldap
    )

    Write-Debug "[$(Get-Date)][Get-RootDse] Begin"

    If ($Script:g_rootDSE) {
        return $Script:g_rootDSE
    }

    [System.DirectoryServices.Protocols.SearchRequest] $request = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList @(
        $null,
        "(objectClass=*)",
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        $null
    )

    $LdapRootDSE = [System.DirectoryServices.Protocols.SearchResponse] $Ldap.SendRequest($request)

    $rootDSE = @{}

    ForEach ($attrName in $LdapRootDSE.entries.Attributes.AttributeNames) {
        $rootDSE[$attrName] = $LdapRootDSE.entries.Attributes[$attrName].GetValues([String])
    }

    $Script:g_rootDSE = $rootDSE

    Write-Output $rootDSE

    Write-Debug "[$(Get-Date)][Get-RootDse] End"
}

Function Get-DefaultNamingContext
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection] $Ldap
    )

    Write-Debug "[$(Get-Date)][Get-DefaultNamingContext] Begin"

    $rootDSE = Get-RootDse $Ldap
    Write-Output $rootDSE.defaultnamingcontext

    Write-Debug "[$(Get-Date)][Get-DefaultNamingContext] End"
}

Function Get-ConfigurationNamingContext
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection] $Ldap
    )

    Write-Debug "[$(Get-Date)][Get-DefaultNamingContext] Begin"
    
    $rootDSE = Get-RootDse $Ldap
    Write-Output $rootDSE.configurationnamingcontext

    Write-Debug "[$(Get-Date)][Get-DefaultNamingContext] End"
}

Function Get-CurrentDomainControllers
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection] $Ldap,

        [Parameter(Mandatory = $true)]
        [String] $ConfigurationNC
    )

    Write-Debug "[$(Get-Date)][Get-CurrentDomainControllers] Begin"

    [System.DirectoryServices.Protocols.SearchRequest] $request = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList @(
        $ConfigurationNC,
        "(objectClass=server)",
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        $null
    )

    $LdapDomainControllers = [System.DirectoryServices.Protocols.SearchResponse] $Ldap.SendRequest($request)

    $domainControllers = @{}

    ForEach ($entry in $LdapDomainControllers.entries) {
        $domainControllers[$entry.DistinguishedName] = @{}
        ForEach ($attrName in $entry.Attributes.AttributeNames) {
            $attrValue = $entry.Attributes[$attrName].GetValues([String])
            If ($attrValue.Count -gt 1) {
                $domainControllers[$entry.DistinguishedName][$attrName] = $attrValue
            } Else {
                $domainControllers[$entry.DistinguishedName][$attrName] = $attrValue[0]
            }
        }
    }

    Write-Debug "[$(Get-Date)][Get-CurrentDomainControllers] End"

    return $domainControllers
}

Function New-BindedLdapConnection
{
    param(
        [Parameter(Mandatory = $true)]
        [String] $Server,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCredential] $Credential = $null
    )

    Write-Debug "[$(Get-Date)][New-BindedLdapConnection] Begin"

    $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection $Server
    $ldap.SessionOptions.ProtocolVersion = 3
    $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    If ($Credential) {
        $cred = New-Object System.Net.NetworkCredential $Credential.UserName, $Credential.Password
        $ldap.Bind($cred)
    }
    $ldap.AutoBind = $true

    Write-Output $ldap

    Write-Debug "[$(Get-Date)][New-BindedLdapConnection] End"
}

Function Get-LogonDomainController
{
    Write-Debug "[$(Get-Date)][Get-CurrentDomainController] Begin"
    Write-Output "$($env:LogonServer -replace '^\\\\').$($env:UserDnsDomain)"
    Write-Debug "[$(Get-Date)][Get-CurrentDomainController] End"
}

Function Trap-DCShadowAttempt
{
    <#
.SYNOPSIS
Dynamically find out if DCShadow is being exploited
.DESCRIPTION
The TrapDCShadowAttempt module exports the Trap-DCShadow function, which will dynamically find out if DCShadow is exploited on a domain.
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
.OUTPUTS
[PSCustomObject] Object with 2 main members:
* Server: information about the server object added by DCShadow
* Reasons: the reasons why the object is considered suspicious
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [String] $Server = '',

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCredential] $Credential = $null
    )

    Write-Debug "[$(Get-Date)][Trap-DCShadowAttempt] Begin"

    If (-not $Server) {
        $Server = Get-LogonDomainController
    }
    
    $ldapConnection = New-BindedLdapConnection $Server $Credential

    $defaultNC = Get-DefaultNamingContext $ldapConnection
    $configurationNC = Get-ConfigurationNamingContext $ldapConnection
    $searchScope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $siteCN = "CN=Sites,$configurationNC"
    $domainControllers = Get-CurrentDomainControllers $ldapConnection $configurationNC

    $Infos = [PSCustomObject] @{
        LdapConnection = $LdapConnection
        DomainControllersOU = "OU=Domain Controllers,$defaultNC"
        DomainControllers = $domainControllers
        DefaultNC = $defaultNC
        SitesCN = $siteCN
        DCNeedingProof = @{
            server = @{}
            ntdsdsa = @{}
        }
    }

    $searchResults = @()
    $searchResults += Register-LdapSearch $Infos $defaultNC $searchScope
    $searchResults += Register-LdapSearch $Infos $siteCN $searchScope

    Write-Information "Trapping any DCShadow attempt (type 'q' to abort, ctrl+c will discard output)..."

    $Continue = $true
    Try {
        While ($Continue) {
            While (![Console]::KeyAvailable) {
                Start-Sleep 1

                # Test for suspicious elements in server objects
                $results = @()
                ForEach ($serverDn in $Infos.DCNeedingProof['server'].Keys) {
                    Write-Debug "[$(Get-Date)][Trap-DCShadowAttempt]  Testing server $serverDn"
                    Test-ServerDCShadow $serverDn $Infos | % { $results += $_ }
                }
                ForEach ($result in $results) {
                    If ($result.Type -eq 'NeedClean') {
                        $Infos.DCNeedingProof['server'].Remove($result.ServerDn)
                    } Else {
                        $result.PSObject.Properties.Remove('Type')
                        Write-Host -ForegroundColor Red -BackgroundColor Black "DCShadow attempt has been detected"
                        Write-Output $result
                    }
                }
            }

            $k = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown')
            If ($k.Character -eq 'q') {
                $Continue = $false
            }
        }
    } Catch {
        Write-Error $_
    } Finally {
        Write-Information "Not trapping DCShadow attempts anymore."
        Get-EventSubscriber | Unregister-Event
        Dispose-LdapSearches $ldapConnection $searchResults
    }

    Write-Debug "[$(Get-Date)][Trap-DCShadowAttempt] End"
}
Export-ModuleMember -Function Trap-DCShadowAttempt
