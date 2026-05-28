#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Migration des objets AD actifs vers AD LDS pour analyse RBAC et modélisation de délégation.
.DESCRIPTION
    Exporte depuis Active Directory les utilisateurs, groupes de sécurité, ordinateurs et
    délégations (ACL sur OUs) vers une instance AD LDS, en filtrant les objets inactifs
    depuis plus de N jours. Les appartenances aux groupes sont mappées pour permettre la
    construction d'un modèle RBAC et d'un modèle de délégation administrative.

    Les objets sont stockés dans LDS sous forme d'inetOrgPerson avec les métadonnées
    étendues sérialisées en JSON dans l'attribut description — compatible avec le schéma
    LDS par défaut, sans extension obligatoire.

.NOTES
    Prérequis :
      - Module PowerShell ActiveDirectory installé (RSAT-AD-PowerShell)
      - Instance AD LDS configurée et accessible
      - Droits en lecture sur l'AD source (incluant Read Control sur les OUs pour les ACL)
      - Droits en écriture sur l'instance LDS cible

.EXAMPLE
    .\Export-ADToLDS.ps1 -LDSServer "lds01" -LDSPort 50389 -LDSBaseDN "DC=rbac,DC=corp,DC=local"

.EXAMPLE
    .\Export-ADToLDS.ps1 -LDSServer "lds01" -LDSPort 50389 -LDSBaseDN "DC=rbac,DC=corp,DC=local" `
        -ADSearchBase "OU=Corp,DC=corp,DC=local" -InactivityThresholdDays 90 `
        -LDSCredential (Get-Credential) -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$LDSServer,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$LDSPort = 389,

    [Parameter(Mandatory)]
    [string]$LDSBaseDN,

    [Parameter()]
    [string]$ADSearchBase,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactivityThresholdDays = 180,

    [Parameter()]
    [System.Management.Automation.PSCredential]$LDSCredential,

    [Parameter()]
    [string]$LogPath = ".\AD-LDS-Migration_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [Parameter()]
    [string]$ReportPath = ".\AD-LDS-Migration_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter()]
    [switch]$SkipUsers,

    [Parameter()]
    [switch]$SkipGroups,

    [Parameter()]
    [switch]$SkipComputers,

    [Parameter()]
    [switch]$SkipDelegations
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region --- VARIABLES GLOBALES ---

$Script:LDSTarget = "$LDSServer`:$LDSPort"
$Script:CutoffDate = (Get-Date).AddDays(-$InactivityThresholdDays)
$Script:CutoffFileTime = $Script:CutoffDate.ToFileTimeUtc()

$Script:Stats = @{
    Users       = @{ Total = 0; Active = 0; Exported = 0; Skipped = 0; Failed = 0 }
    Groups      = @{ Total = 0; Exported = 0; Skipped = 0; Failed = 0 }
    Computers   = @{ Total = 0; Active = 0; Exported = 0; Skipped = 0; Failed = 0 }
    Delegations = @{ Total = 0; Exported = 0; Failed = 0 }
    Memberships = @{ Total = 0; Success = 0; Failed = 0 }
}

$Script:ReportData = [System.Collections.Generic.List[pscustomobject]]::new()
$Script:UserDNMap  = @{}   # samAccountName → DN LDS
$Script:GroupDNMap = @{}   # samAccountName → DN LDS
$Script:OUs        = @{}   # clés : Users, Groups, Computers, Delegations

#endregion

#region --- LOGGING ---

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'SECTION')][string]$Level = 'INFO'
    )
    $ts     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = switch ($Level) {
        'INFO'    { '[INFO   ]' }
        'WARN'    { '[WARN   ]' }
        'ERROR'   { '[ERROR  ]' }
        'SUCCESS' { '[SUCCESS]' }
        'SECTION' { '[=======]' }
    }
    $line = "$ts $prefix $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    $color = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        'SUCCESS' { 'Green' }
        'SECTION' { 'Cyan' }
        default   { 'White' }
    }
    Write-Host $line -ForegroundColor $color
}

function Add-ReportEntry {
    param(
        [string]$ObjectType,
        [string]$Name,
        [string]$SamAccountName,
        [string]$SourceDN,
        [string]$TargetDN,
        [string]$Status,
        [string]$Notes = ''
    )
    $Script:ReportData.Add([pscustomobject]@{
        Timestamp      = Get-Date -Format 'o'
        ObjectType     = $ObjectType
        Name           = $Name
        SamAccountName = $SamAccountName
        SourceDN       = $SourceDN
        TargetDN       = $TargetDN
        Status         = $Status
        Notes          = $Notes
    })
}

#endregion

#region --- HELPERS LDS (System.DirectoryServices) ---

function Get-LDSDirectoryEntry {
    param([Parameter(Mandatory)][string]$DN)

    $path = "LDAP://$($Script:LDSTarget)/$DN"
    if ($LDSCredential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $path,
            $LDSCredential.UserName,
            $LDSCredential.GetNetworkCredential().Password
        )
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry($path)
    }
}

function Test-LDSObjectExists {
    param([Parameter(Mandatory)][string]$DN)
    try {
        $de = Get-LDSDirectoryEntry -DN $DN
        $null = $de.Properties['cn'].Value
        return $true
    }
    catch { return $false }
}

function New-LDSOU {
    param(
        [Parameter(Mandatory)][string]$ParentDN,
        [Parameter(Mandatory)][string]$OUName
    )
    $ouDN = "OU=$OUName,$ParentDN"
    if (Test-LDSObjectExists -DN $ouDN) {
        Write-Log "OU existante : $ouDN"
        return $ouDN
    }
    try {
        $parent = Get-LDSDirectoryEntry -DN $ParentDN
        $ou = $parent.Children.Add("OU=$OUName", 'organizationalUnit')
        $ou.Properties['ou'].Value = $OUName
        if ($PSCmdlet.ShouldProcess($ouDN, 'Créer OU LDS')) {
            $ou.CommitChanges()
            Write-Log "OU créée : $ouDN" -Level SUCCESS
        }
    }
    catch {
        throw "Impossible de créer l'OU '$ouDN' : $_"
    }
    return $ouDN
}

function New-LDSInetOrgPerson {
    <#
    .SYNOPSIS
        Crée un objet inetOrgPerson dans LDS avec les attributs fournis.
        Retourne le DN de l'objet créé.
    #>
    param(
        [Parameter(Mandatory)][string]$ParentDN,
        [Parameter(Mandatory)][string]$CN,
        [Parameter(Mandatory)][hashtable]$Attributes
    )

    $parent = Get-LDSDirectoryEntry -DN $ParentDN
    $obj    = $parent.Children.Add("CN=$CN", 'inetOrgPerson')

    # sn est obligatoire pour inetOrgPerson (RFC 2798)
    $obj.Properties['sn'].Value = if ($Attributes['sn']) { $Attributes['sn'] } else { $CN }

    # Attributs standard inetOrgPerson disponibles sans extension de schéma
    $supportedAttrs = @('givenName', 'displayName', 'mail', 'o', 'ou', 'title', 'telephoneNumber', 'description')
    foreach ($attr in $supportedAttrs) {
        if ($Attributes.ContainsKey($attr) -and $null -ne $Attributes[$attr] -and $Attributes[$attr] -ne '') {
            try { $obj.Properties[$attr].Value = [string]$Attributes[$attr] }
            catch { Write-Log "Attribut '$attr' ignoré pour '$CN' : $_" -Level WARN }
        }
    }

    $obj.CommitChanges()
    return "CN=$CN,$ParentDN"
}

function Update-LDSDescription {
    <#
    .SYNOPSIS
        Met à jour l'attribut description d'un objet LDS existant (JSON fusionné).
    #>
    param(
        [Parameter(Mandatory)][string]$DN,
        [Parameter(Mandatory)][hashtable]$ExtraFields
    )
    $de = Get-LDSDirectoryEntry -DN $DN
    $de.RefreshCache()
    $existing = $de.Properties['description'].Value

    $data = @{}
    if ($existing) {
        ($existing | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $data[$_.Name] = $_.Value }
    }
    foreach ($k in $ExtraFields.Keys) { $data[$k] = $ExtraFields[$k] }

    $de.Properties['description'].Value = ($data | ConvertTo-Json -Compress -Depth 4)
    $de.CommitChanges()
}

function Initialize-LDSStructure {
    Write-Log '=== Initialisation de la structure LDS ===' -Level SECTION

    if (-not (Test-LDSObjectExists -DN $LDSBaseDN)) {
        throw "Le BaseDN '$LDSBaseDN' est introuvable dans LDS. Vérifiez la configuration de l'instance."
    }

    $Script:OUs['Users']       = New-LDSOU -ParentDN $LDSBaseDN -OUName 'Users'
    $Script:OUs['Groups']      = New-LDSOU -ParentDN $LDSBaseDN -OUName 'Groups'
    $Script:OUs['Computers']   = New-LDSOU -ParentDN $LDSBaseDN -OUName 'Computers'
    $Script:OUs['Delegations'] = New-LDSOU -ParentDN $LDSBaseDN -OUName 'Delegations'

    Write-Log 'Structure LDS prête.' -Level SUCCESS
}

#endregion

#region --- EXPORT DES UTILISATEURS ---

function Export-UsersToLDS {
    Write-Log '=== Export des utilisateurs ===' -Level SECTION

    $props = @(
        'SamAccountName', 'DisplayName', 'GivenName', 'Surname', 'UserPrincipalName',
        'EmailAddress', 'Department', 'Title', 'Manager', 'DistinguishedName',
        'MemberOf', 'LastLogonDate', 'PasswordLastSet', 'whenCreated',
        'Enabled', 'EmployeeID', 'EmployeeType', 'Office', 'TelephoneNumber',
        'Company', 'Division', 'Description'
    )

    # Filtre LDAP : comptes actifs dont lastLogonTimestamp OU pwdLastSet est récent
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)" +
                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                  "(|(lastLogonTimestamp>=$($Script:CutoffFileTime))(pwdLastSet>=$($Script:CutoffFileTime))))"

    $adParams = @{ LdapFilter = $ldapFilter; Properties = $props }
    if ($ADSearchBase) { $adParams['SearchBase'] = $ADSearchBase }

    Write-Log "Seuil d'inactivité : $($Script:CutoffDate.ToString('yyyy-MM-dd')) ($InactivityThresholdDays jours)"
    Write-Log 'Récupération des utilisateurs actifs depuis AD...'

    $users = @(Get-ADUser @adParams)
    $Script:Stats.Users.Active = $users.Count
    $Script:Stats.Users.Total  = @(Get-ADUser -Filter { Enabled -eq $true }).Count
    Write-Log "Utilisateurs actifs : $($Script:Stats.Users.Active) / $($Script:Stats.Users.Total) au total"

    $i = 0
    foreach ($user in $users) {
        $i++
        Write-Progress -Activity 'Export utilisateurs' -Status $user.SamAccountName `
                       -PercentComplete (($i / [Math]::Max(1, $users.Count)) * 100)

        $cn = ($user.SamAccountName -replace '[,=+<>#;"\\\/]', '_').Substring(0, [Math]::Min(64, $user.SamAccountName.Length))
        $targetDN = "CN=$cn,$($Script:OUs['Users'])"

        if (Test-LDSObjectExists -DN $targetDN) {
            Write-Log "Déjà présent, ignoré : $cn" -Level WARN
            $Script:Stats.Users.Skipped++
            $Script:UserDNMap[$user.SamAccountName] = $targetDN
            Add-ReportEntry 'User' $user.DisplayName $user.SamAccountName $user.DistinguishedName $targetDN 'Skipped' 'Objet déjà présent'
            continue
        }

        $memberOfNames = @($user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
        $managerName   = if ($user.Manager) { ($user.Manager -split ',')[0] -replace '^CN=' } else { '' }
        $lastLogon     = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('o') } else { '' }
        $pwdSet        = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') } else { '' }
        $created       = if ($user.whenCreated) { $user.whenCreated.ToString('o') } else { '' }

        $meta = @{
            objectType      = 'user'
            samAccountName  = $user.SamAccountName
            upn             = "$($user.UserPrincipalName)"
            department      = "$($user.Department)"
            company         = "$($user.Company)"
            office          = "$($user.Office)"
            employeeID      = "$($user.EmployeeID)"
            employeeType    = "$($user.EmployeeType)"
            manager         = $managerName
            whenCreated     = $created
            lastLogonDate   = $lastLogon
            passwordLastSet = $pwdSet
            adDN            = $user.DistinguishedName
            memberOf        = ($memberOfNames -join '|')
        }

        $attrs = @{
            sn          = if ($user.Surname) { $user.Surname } else { $user.SamAccountName }
            givenName   = "$($user.GivenName)"
            displayName = "$($user.DisplayName)"
            mail        = "$($user.EmailAddress)"
            title       = "$($user.Title)"
            o           = "$($user.Department)"
            telephoneNumber = "$($user.TelephoneNumber)"
            description = ($meta | ConvertTo-Json -Compress -Depth 3)
        }

        try {
            if ($PSCmdlet.ShouldProcess($targetDN, 'Créer utilisateur LDS')) {
                New-LDSInetOrgPerson -ParentDN $Script:OUs['Users'] -CN $cn -Attributes $attrs | Out-Null
            }
            $Script:UserDNMap[$user.SamAccountName] = $targetDN
            $Script:Stats.Users.Exported++
            Add-ReportEntry 'User' $user.DisplayName $user.SamAccountName $user.DistinguishedName $targetDN 'Success'
        }
        catch {
            Write-Log "Échec utilisateur '$($user.SamAccountName)' : $_" -Level ERROR
            $Script:Stats.Users.Failed++
            Add-ReportEntry 'User' $user.DisplayName $user.SamAccountName $user.DistinguishedName $targetDN 'Failed' "$_"
        }
    }

    Write-Progress -Activity 'Export utilisateurs' -Completed
    Write-Log "Utilisateurs — Exportés: $($Script:Stats.Users.Exported) | Ignorés: $($Script:Stats.Users.Skipped) | Échecs: $($Script:Stats.Users.Failed)" -Level SUCCESS
}

#endregion

#region --- EXPORT DES GROUPES ---

function Export-GroupsToLDS {
    Write-Log '=== Export des groupes de sécurité ===' -Level SECTION

    $props = @(
        'SamAccountName', 'Name', 'GroupScope', 'GroupCategory', 'Description',
        'ManagedBy', 'DistinguishedName', 'Members', 'MemberOf', 'whenCreated', 'AdminCount'
    )

    $adParams = @{ Filter = { GroupCategory -eq 'Security' }; Properties = $props }
    if ($ADSearchBase) { $adParams['SearchBase'] = $ADSearchBase }

    Write-Log 'Récupération des groupes de sécurité depuis AD...'
    $groups = @(Get-ADGroup @adParams)
    $Script:Stats.Groups.Total = $groups.Count
    Write-Log "Groupes de sécurité trouvés : $($Script:Stats.Groups.Total)"

    $i = 0
    foreach ($group in $groups) {
        $i++
        Write-Progress -Activity 'Export groupes' -Status $group.SamAccountName `
                       -PercentComplete (($i / [Math]::Max(1, $groups.Count)) * 100)

        $cn = ($group.SamAccountName -replace '[,=+<>#;"\\\/]', '_').Substring(0, [Math]::Min(64, $group.SamAccountName.Length))
        $targetDN = "CN=$cn,$($Script:OUs['Groups'])"

        if (Test-LDSObjectExists -DN $targetDN) {
            Write-Log "Déjà présent, ignoré : $cn" -Level WARN
            $Script:Stats.Groups.Skipped++
            $Script:GroupDNMap[$group.SamAccountName] = $targetDN
            continue
        }

        $memberOfNames  = @($group.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
        $managedByName  = if ($group.ManagedBy) { ($group.ManagedBy -split ',')[0] -replace '^CN=' } else { '' }
        $created        = if ($group.whenCreated) { $group.whenCreated.ToString('o') } else { '' }
        $memberCount    = @($group.Members).Count
        $memberSample   = ($group.Members | Select-Object -First 20 |
                           ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join '|'

        $meta = @{
            objectType   = 'group'
            samAccountName = $group.SamAccountName
            groupScope   = $group.GroupScope.ToString()
            groupCategory= $group.GroupCategory.ToString()
            managedBy    = $managedByName
            adminCount   = $group.AdminCount
            memberCount  = $memberCount
            memberSample = $memberSample
            whenCreated  = $created
            adDN         = $group.DistinguishedName
            memberOf     = ($memberOfNames -join '|')
        }

        $attrs = @{
            sn          = $group.Name
            displayName = $group.Name
            o           = $group.GroupScope.ToString()
            title       = $group.GroupCategory.ToString()
            description = ($meta | ConvertTo-Json -Compress -Depth 3)
        }

        try {
            if ($PSCmdlet.ShouldProcess($targetDN, 'Créer groupe LDS')) {
                New-LDSInetOrgPerson -ParentDN $Script:OUs['Groups'] -CN $cn -Attributes $attrs | Out-Null
            }
            $Script:GroupDNMap[$group.SamAccountName] = $targetDN
            $Script:Stats.Groups.Exported++
            Add-ReportEntry 'Group' $group.Name $group.SamAccountName $group.DistinguishedName $targetDN 'Success'
        }
        catch {
            Write-Log "Échec groupe '$($group.SamAccountName)' : $_" -Level ERROR
            $Script:Stats.Groups.Failed++
            Add-ReportEntry 'Group' $group.Name $group.SamAccountName $group.DistinguishedName $targetDN 'Failed' "$_"
        }
    }

    Write-Progress -Activity 'Export groupes' -Completed
    Write-Log "Groupes — Exportés: $($Script:Stats.Groups.Exported) | Ignorés: $($Script:Stats.Groups.Skipped) | Échecs: $($Script:Stats.Groups.Failed)" -Level SUCCESS
}

#endregion

#region --- EXPORT DES ORDINATEURS ---

function Export-ComputersToLDS {
    Write-Log '=== Export des ordinateurs ===' -Level SECTION

    $props = @(
        'Name', 'SamAccountName', 'DNSHostName', 'OperatingSystem', 'OperatingSystemVersion',
        'OperatingSystemServicePack', 'Location', 'ManagedBy', 'DistinguishedName',
        'LastLogonDate', 'whenCreated', 'Enabled', 'IPv4Address', 'MemberOf',
        'ServicePrincipalNames', 'Description'
    )

    $ldapFilter = "(&(objectCategory=computer)(objectClass=computer)" +
                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                  "(lastLogonTimestamp>=$($Script:CutoffFileTime)))"

    $adParams = @{ LdapFilter = $ldapFilter; Properties = $props }
    if ($ADSearchBase) { $adParams['SearchBase'] = $ADSearchBase }

    Write-Log "Seuil d'inactivité : $($Script:CutoffDate.ToString('yyyy-MM-dd'))"
    Write-Log 'Récupération des ordinateurs actifs depuis AD...'

    $computers = @(Get-ADComputer @adParams)
    $Script:Stats.Computers.Active = $computers.Count
    $Script:Stats.Computers.Total  = @(Get-ADComputer -Filter { Enabled -eq $true }).Count
    Write-Log "Ordinateurs actifs : $($Script:Stats.Computers.Active) / $($Script:Stats.Computers.Total) au total"

    $i = 0
    foreach ($comp in $computers) {
        $i++
        Write-Progress -Activity 'Export ordinateurs' -Status $comp.Name `
                       -PercentComplete (($i / [Math]::Max(1, $computers.Count)) * 100)

        $cn = ($comp.Name -replace '[,=+<>#;"\\\/]', '_').Substring(0, [Math]::Min(64, $comp.Name.Length))
        $targetDN = "CN=$cn,$($Script:OUs['Computers'])"

        if (Test-LDSObjectExists -DN $targetDN) {
            Write-Log "Déjà présent, ignoré : $cn" -Level WARN
            $Script:Stats.Computers.Skipped++
            continue
        }

        $memberOfNames = @($comp.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
        $managedByName = if ($comp.ManagedBy) { ($comp.ManagedBy -split ',')[0] -replace '^CN=' } else { '' }
        $lastLogon     = if ($comp.LastLogonDate) { $comp.LastLogonDate.ToString('o') } else { '' }
        $created       = if ($comp.whenCreated) { $comp.whenCreated.ToString('o') } else { '' }
        $spns          = ($comp.ServicePrincipalNames -join '|')

        $meta = @{
            objectType            = 'computer'
            samAccountName        = $comp.SamAccountName
            dnsHostName           = "$($comp.DNSHostName)"
            operatingSystem       = "$($comp.OperatingSystem)"
            operatingSystemVersion= "$($comp.OperatingSystemVersion)"
            osSP                  = "$($comp.OperatingSystemServicePack)"
            location              = "$($comp.Location)"
            managedBy             = $managedByName
            ipv4Address           = "$($comp.IPv4Address)"
            servicePrincipalNames = $spns
            whenCreated           = $created
            lastLogonDate         = $lastLogon
            adDN                  = $comp.DistinguishedName
            memberOf              = ($memberOfNames -join '|')
        }

        $attrs = @{
            sn          = $comp.Name
            displayName = $comp.Name
            o           = "$($comp.OperatingSystem)"
            title       = 'computer'
            description = ($meta | ConvertTo-Json -Compress -Depth 3)
        }

        try {
            if ($PSCmdlet.ShouldProcess($targetDN, 'Créer ordinateur LDS')) {
                New-LDSInetOrgPerson -ParentDN $Script:OUs['Computers'] -CN $cn -Attributes $attrs | Out-Null
            }
            $Script:Stats.Computers.Exported++
            Add-ReportEntry 'Computer' $comp.Name $comp.SamAccountName $comp.DistinguishedName $targetDN 'Success'
        }
        catch {
            Write-Log "Échec ordinateur '$($comp.Name)' : $_" -Level ERROR
            $Script:Stats.Computers.Failed++
            Add-ReportEntry 'Computer' $comp.Name $comp.SamAccountName $comp.DistinguishedName $targetDN 'Failed' "$_"
        }
    }

    Write-Progress -Activity 'Export ordinateurs' -Completed
    Write-Log "Ordinateurs — Exportés: $($Script:Stats.Computers.Exported) | Ignorés: $($Script:Stats.Computers.Skipped) | Échecs: $($Script:Stats.Computers.Failed)" -Level SUCCESS
}

#endregion

#region --- EXPORT DES DELEGATIONS (ACL) ---

function Get-ADSchemaGuidMap {
    <#
    .SYNOPSIS
        Construit une table GUID → nom lisible à partir du schéma AD et des droits étendus.
        Permet de décoder les ObjectType / InheritedObjectType dans les ACEs.
    #>
    Write-Log 'Construction de la table GUID schéma AD (peut prendre quelques secondes)...'

    $rootDSE   = Get-ADRootDSE
    $schemaNC  = $rootDSE.schemaNamingContext
    $configNC  = $rootDSE.configurationNamingContext
    $guidMap   = @{}

    # Attributs et classes du schéma
    Get-ADObject -SearchBase $schemaNC -LdapFilter '(schemaIDGUID=*)' -Properties schemaIDGUID, name |
        ForEach-Object {
            try {
                $g = ([guid]$_.schemaIDGUID).ToString()
                $guidMap[$g] = $_.name
            }
            catch {}
        }

    # Droits étendus (Extended Rights / Control Access Rights)
    Get-ADObject -SearchBase "CN=Extended-Rights,$configNC" -LdapFilter '(rightsGuid=*)' `
                 -Properties rightsGuid, displayName |
        ForEach-Object {
            if ($_.rightsGuid) { $guidMap[$_.rightsGuid] = $_.displayName }
        }

    Write-Log "Table GUID chargée : $($guidMap.Count) entrées."
    return $guidMap
}

function Export-DelegationsToLDS {
    Write-Log '=== Export des délégations (analyse ACL) ===' -Level SECTION

    # Charger le drive AD si nécessaire
    if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        New-PSDrive -Name AD -PSProvider ActiveDirectory -Root '' -ErrorAction Stop | Out-Null
    }

    $searchBase = if ($ADSearchBase) { $ADSearchBase } else { (Get-ADDomain).DistinguishedName }
    $guidMap    = Get-ADSchemaGuidMap

    Write-Log "Analyse des ACL sur les OUs de : $searchBase"
    $ous = @(Get-ADOrganizationalUnit -SearchBase $searchBase -Filter * -Properties DistinguishedName)
    Write-Log "Nombre d'OUs à analyser : $($ous.Count)"

    $i = 0
    foreach ($ou in $ous) {
        $i++
        Write-Progress -Activity 'Analyse délégations' -Status $ou.DistinguishedName `
                       -PercentComplete (($i / [Math]::Max(1, $ous.Count)) * 100)

        try {
            $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction Stop
        }
        catch {
            Write-Log "Impossible de lire l'ACL de '$($ou.DistinguishedName)' : $_" -Level WARN
            continue
        }

        # Filtre : ACEs explicites (non héritées) excluant les comptes système built-in
        $delegations = $acl.Access | Where-Object {
            -not $_.IsInherited -and
            $_.IdentityReference -notmatch `
                '(^NT AUTHORITY\\|^BUILTIN\\|^S-1-5-1[0-9]$|Everyone|Tout le monde|Creator Owner|CREATOR OWNER)'
        }

        foreach ($ace in $delegations) {
            $Script:Stats.Delegations.Total++

            $emptyGuid = [guid]::Empty.ToString()
            $objTypeName = if ($ace.ObjectType.ToString() -ne $emptyGuid) {
                if ($guidMap.ContainsKey($ace.ObjectType.ToString())) { $guidMap[$ace.ObjectType.ToString()] }
                else { $ace.ObjectType.ToString() }
            }
            else { 'All' }

            $inhTypeName = if ($ace.InheritedObjectType.ToString() -ne $emptyGuid) {
                if ($guidMap.ContainsKey($ace.InheritedObjectType.ToString())) { $guidMap[$ace.InheritedObjectType.ToString()] }
                else { $ace.InheritedObjectType.ToString() }
            }
            else { 'All' }

            $meta = @{
                objectType        = 'delegation'
                ouDN              = $ou.DistinguishedName
                ouName            = ($ou.DistinguishedName -split ',')[0] -replace '^OU='
                identity          = $ace.IdentityReference.ToString()
                adRights          = $ace.ActiveDirectoryRights.ToString()
                accessType        = $ace.AccessControlType.ToString()
                objectTypeName    = $objTypeName
                objectTypeGuid    = $ace.ObjectType.ToString()
                inheritedTypeName = $inhTypeName
                inheritedTypeGuid = $ace.InheritedObjectType.ToString()
                inheritanceFlags  = $ace.InheritanceFlags.ToString()
                propagationFlags  = $ace.PropagationFlags.ToString()
                isInherited       = $ace.IsInherited
            }

            # Construire un CN unique : OU + identité + fragment de GUID
            $ouShort   = ($meta.ouName -replace '[^a-zA-Z0-9_-]', '_').Substring(0, [Math]::Min(20, $meta.ouName.Length))
            $idShort   = ($ace.IdentityReference.Value -replace '[\\/@,=+<>#;"\ ]', '_').Substring(0, [Math]::Min(30, $ace.IdentityReference.Value.Length))
            $guidShort = $ace.ObjectType.ToString().Substring(0, 8)
            $cn = "$ouShort`_$idShort`_$guidShort" -replace '[^a-zA-Z0-9_-]', '_'
            $cn = $cn.Substring(0, [Math]::Min(64, $cn.Length))

            # Déduplication : suffixe numérique si collision
            $targetDN  = "CN=$cn,$($Script:OUs['Delegations'])"
            $suffix    = 0
            while (Test-LDSObjectExists -DN $targetDN) {
                $suffix++
                $baseCn   = $cn.Substring(0, [Math]::Min(60, $cn.Length))
                $cn       = "${baseCn}_${suffix}"
                $targetDN = "CN=$cn,$($Script:OUs['Delegations'])"
            }

            $attrs = @{
                sn          = $meta.ouName
                o           = $ace.ActiveDirectoryRights.ToString()
                title       = $ace.AccessControlType.ToString()
                description = ($meta | ConvertTo-Json -Compress -Depth 3)
            }

            try {
                if ($PSCmdlet.ShouldProcess($targetDN, 'Créer délégation LDS')) {
                    New-LDSInetOrgPerson -ParentDN $Script:OUs['Delegations'] -CN $cn -Attributes $attrs | Out-Null
                }
                $Script:Stats.Delegations.Exported++
                Add-ReportEntry 'Delegation' $cn $ace.IdentityReference.ToString() `
                    $ou.DistinguishedName $targetDN 'Success' $ace.ActiveDirectoryRights.ToString()
            }
            catch {
                Write-Log "Échec délégation '$cn' : $_" -Level ERROR
                $Script:Stats.Delegations.Failed++
                Add-ReportEntry 'Delegation' $cn $ace.IdentityReference.ToString() `
                    $ou.DistinguishedName $targetDN 'Failed' "$_"
            }
        }
    }

    Write-Progress -Activity 'Analyse délégations' -Completed
    Write-Log "Délégations — Trouvées: $($Script:Stats.Delegations.Total) | Exportées: $($Script:Stats.Delegations.Exported) | Échecs: $($Script:Stats.Delegations.Failed)" -Level SUCCESS
}

#endregion

#region --- MAPPING DES APPARTENANCES AUX GROUPES ---

function Set-GroupMemberships {
    Write-Log '=== Mapping des appartenances aux groupes ===' -Level SECTION

    if ($Script:GroupDNMap.Count -eq 0) {
        Write-Log 'Aucun groupe exporté — mapping ignoré.' -Level WARN
        return
    }

    $adParams = @{
        Filter     = { GroupCategory -eq 'Security' }
        Properties = @('SamAccountName', 'Members')
    }
    if ($ADSearchBase) { $adParams['SearchBase'] = $ADSearchBase }

    $groups = @(Get-ADGroup @adParams)
    $total  = $groups.Count
    $i      = 0

    foreach ($group in $groups) {
        $i++
        Write-Progress -Activity 'Mapping memberships' -Status $group.SamAccountName `
                       -PercentComplete (($i / [Math]::Max(1, $total)) * 100)

        if (-not $Script:GroupDNMap.ContainsKey($group.SamAccountName)) { continue }

        $groupLDSDN   = $Script:GroupDNMap[$group.SamAccountName]
        $memberDNsLDS = @()

        foreach ($memberAdDN in @($group.Members)) {
            $Script:Stats.Memberships.Total++
            try {
                $memberObj = Get-ADObject $memberAdDN -Properties SamAccountName -ErrorAction Stop
                $sam = $memberObj.SamAccountName -replace '\$$', ''
                if ($Script:UserDNMap.ContainsKey($sam)) {
                    $memberDNsLDS += $Script:UserDNMap[$sam]
                }
                elseif ($Script:GroupDNMap.ContainsKey($sam)) {
                    $memberDNsLDS += $Script:GroupDNMap[$sam]
                }
            }
            catch {
                Write-Log "Membre non résolu '$memberAdDN' : $_" -Level WARN
            }
        }

        if ($memberDNsLDS.Count -gt 0) {
            try {
                if ($PSCmdlet.ShouldProcess($groupLDSDN, "Stocker $($memberDNsLDS.Count) membres")) {
                    Update-LDSDescription -DN $groupLDSDN -ExtraFields @{ memberDNs = $memberDNsLDS }
                }
                $Script:Stats.Memberships.Success += $memberDNsLDS.Count
                Write-Log "Groupe '$($group.SamAccountName)' : $($memberDNsLDS.Count) membres LDS mappés."
            }
            catch {
                Write-Log "Échec mapping membres pour '$($group.SamAccountName)' : $_" -Level ERROR
                $Script:Stats.Memberships.Failed++
            }
        }
    }

    Write-Progress -Activity 'Mapping memberships' -Completed
    Write-Log "Memberships — Total AD: $($Script:Stats.Memberships.Total) | LDS: $($Script:Stats.Memberships.Success) | Échecs: $($Script:Stats.Memberships.Failed)" -Level SUCCESS
}

#endregion

#region --- RAPPORT FINAL ---

function Export-MigrationReport {
    Write-Log '=== Génération du rapport ===' -Level SECTION

    $Script:ReportData | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Log "Rapport CSV : $ReportPath" -Level SUCCESS

    Write-Log '-----------------------------------------------------------' -Level SECTION
    Write-Log " RÉSUMÉ DE LA MIGRATION" -Level SECTION
    Write-Log '-----------------------------------------------------------' -Level SECTION
    Write-Log ("Utilisateurs   — AD total: {0,6} | Actifs: {1,6} | Exportés: {2,6} | Ignorés: {3,4} | Échecs: {4,4}" -f `
        $Script:Stats.Users.Total, $Script:Stats.Users.Active, $Script:Stats.Users.Exported, `
        $Script:Stats.Users.Skipped, $Script:Stats.Users.Failed)
    Write-Log ("Groupes        — Total:    {0,6} |                | Exportés: {1,6} | Ignorés: {2,4} | Échecs: {3,4}" -f `
        $Script:Stats.Groups.Total, $Script:Stats.Groups.Exported, `
        $Script:Stats.Groups.Skipped, $Script:Stats.Groups.Failed)
    Write-Log ("Ordinateurs    — AD total: {0,6} | Actifs: {1,6} | Exportés: {2,6} | Ignorés: {3,4} | Échecs: {4,4}" -f `
        $Script:Stats.Computers.Total, $Script:Stats.Computers.Active, $Script:Stats.Computers.Exported, `
        $Script:Stats.Computers.Skipped, $Script:Stats.Computers.Failed)
    Write-Log ("Délégations    — Trouvées: {0,6} |                | Exportées: {1,5} |            | Échecs: {2,4}" -f `
        $Script:Stats.Delegations.Total, $Script:Stats.Delegations.Exported, $Script:Stats.Delegations.Failed)
    Write-Log ("Memberships    — Total AD: {0,6} |                | LDS: {1,10} |            | Échecs: {2,4}" -f `
        $Script:Stats.Memberships.Total, $Script:Stats.Memberships.Success, $Script:Stats.Memberships.Failed)
    Write-Log '-----------------------------------------------------------' -Level SECTION
}

#endregion

#region --- POINT D'ENTRÉE ---

function Main {
    $domain = try { (Get-ADDomain).DistinguishedName } catch { 'inconnu' }
    $source = if ($ADSearchBase) { $ADSearchBase } else { $domain }

    Write-Log ('=' * 65) -Level SECTION
    Write-Log " Démarrage  : $(Get-Date -Format 'o')" -Level SECTION
    Write-Log " Source AD  : $source" -Level SECTION
    Write-Log " Cible LDS  : $($Script:LDSTarget)  BaseDN=$LDSBaseDN" -Level SECTION
    Write-Log " Inactivité : $InactivityThresholdDays jours (seuil: $($Script:CutoffDate.ToString('yyyy-MM-dd')))" -Level SECTION
    Write-Log ('=' * 65) -Level SECTION

    try {
        Initialize-LDSStructure

        if (-not $SkipUsers)       { Export-UsersToLDS }
        if (-not $SkipGroups)      { Export-GroupsToLDS }
        if (-not $SkipComputers)   { Export-ComputersToLDS }
        if (-not $SkipDelegations) { Export-DelegationsToLDS }

        # Le mapping des memberships dépend que les utilisateurs ET les groupes soient exportés
        if (-not $SkipGroups)      { Set-GroupMemberships }

        Export-MigrationReport

        Write-Log 'Migration terminée avec succès.' -Level SUCCESS
        Write-Log "Log     : $LogPath"
        Write-Log "Rapport : $ReportPath"
    }
    catch {
        Write-Log "ERREUR CRITIQUE — $_" -Level ERROR
        Write-Log $_.ScriptStackTrace -Level ERROR
        Export-MigrationReport
        exit 1
    }
}

Main

#endregion
