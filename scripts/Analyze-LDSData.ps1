#Requires -Version 5.1

<#
.SYNOPSIS
    Analyse les données RBAC exportées dans AD LDS et produit des rapports CSV d'analyse.
.DESCRIPTION
    Lit les objets inetOrgPerson stockés par Export-ADToLDS.ps1 dans l'instance LDS,
    décode les métadonnées JSON et produit dans AnalysisPath :

      groups_<ts>.csv                  - Tous les groupes avec comptages et niveaux de risque
      users_<ts>.csv                   - Tous les utilisateurs avec score de privilège
      delegations_<ts>.csv             - Toutes les délégations avec scoring de risque
      computers_<ts>.csv               - Tous les ordinateurs actifs
      empty-groups_<ts>.csv            - Groupes sans membres (candidats à suppression)
      over-privileged-users_<ts>.csv   - Utilisateurs membres de trop de groupes
      high-risk-delegations_<ts>.csv   - Délégations Critical/High
      delegation-by-ou_<ts>.csv        - Carte des droits par OU
      delegation-by-identity_<ts>.csv  - Carte des droits par identité
      rbac-candidates_<ts>.csv         - Corrélation département ↔ groupes (candidats rôles)

.EXAMPLE
    .\Analyze-LDSData.ps1 -LDSServer "lds01" -LDSPort 50389 -LDSBaseDN "DC=rbac,DC=corp,DC=local"

.EXAMPLE
    .\Analyze-LDSData.ps1 -LDSServer "lds01" -LDSPort 50389 -LDSBaseDN "DC=rbac,DC=corp,DC=local" `
        -OverPrivilegedThreshold 15 -AnalysisPath "C:\Reports\RBAC"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LDSServer,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$LDSPort = 389,

    [Parameter(Mandatory)]
    [string]$LDSBaseDN,

    [Parameter()]
    [System.Management.Automation.PSCredential]$LDSCredential,

    [Parameter()]
    [string]$AnalysisPath = ".\analysis",

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$OverPrivilegedThreshold = 10,

    [Parameter()]
    [string]$LogPath = ".\AD-LDS-Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Script:LDSTarget = "$LDSServer`:$LDSPort"
$Script:Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

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

#endregion

#region --- LDS READER ---

function Get-LDSDirectoryEntry {
    param([Parameter(Mandatory)][string]$DN)
    $path = "LDAP://$($Script:LDSTarget)/$DN"
    if ($LDSCredential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $path,
            $LDSCredential.UserName,
            $LDSCredential.GetNetworkCredential().Password
        )
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($path)
    }
}

function Read-LDSOUObjects {
    <#
    .SYNOPSIS
        Lit tous les inetOrgPerson d'une OU LDS. Retourne un tableau d'objets
        avec CN, DisplayName et un hashtable Meta issu du JSON description.
        Retourne un tableau vide si l'OU est inaccessible (ex. export partiel).
    #>
    param([Parameter(Mandatory)][string]$OUDN)

    $de = $null
    $searcher = $null
    $objects = [System.Collections.Generic.List[pscustomobject]]::new()

    try {
        $de = Get-LDSDirectoryEntry -DN $OUDN
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
        $searcher.Filter = "(objectClass=inetOrgPerson)"
        $searcher.PageSize = 1000
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        [void]$searcher.PropertiesToLoad.AddRange(@('cn', 'description', 'displayName'))

        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $descRaw = if ($r.Properties['description'].Count) { $r.Properties['description'][0] } else { $null }
            $meta = @{}
            if ($descRaw) {
                try {
                    $parsed = $descRaw | ConvertFrom-Json
                    $parsed.PSObject.Properties | ForEach-Object { $meta[$_.Name] = $_.Value }
                } catch {
                    Write-Log "JSON invalide pour CN=$($r.Properties['cn'][0]) : $_" -Level WARN
                }
            }
            $objects.Add([pscustomobject]@{
                CN          = $r.Properties['cn'][0]
                DisplayName = if ($r.Properties['displayName'].Count) { $r.Properties['displayName'][0] } else { '' }
                Meta        = $meta
            })
        }
        $results.Dispose()
    } catch {
        Write-Log "Impossible de lire l'OU '$OUDN' : $_ (export partiel ?)" -Level WARN
    } finally {
        if ($searcher) { $searcher.Dispose() }
        if ($de) { $de.Dispose() }
    }
    return $objects
}

#endregion

#region --- ANALYSEURS ---

function ConvertTo-GroupAnalysis {
    param($Groups)

    Write-Log '=== Analyse des groupes ===' -Level SECTION

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($g in $Groups) {
        $m           = $g.Meta
        $memberCount = if ($m.ContainsKey('memberCount')) { [int]$m['memberCount'] } else { 0 }
        $memberOf    = if ($m.ContainsKey('memberOf') -and $m['memberOf']) {
                           @($m['memberOf'] -split '\|' | Where-Object { $_ })
                       } else { @() }
        $adminCount  = if ($m.ContainsKey('adminCount')) { [int]$m['adminCount'] } else { 0 }
        $risk = if ($adminCount -gt 0)       { 'Admin' }
                elseif ($memberCount -eq 0)  { 'Empty' }
                elseif ($memberCount -gt 500){ 'LargeGroup' }
                else                         { 'Normal' }

        $rows.Add([pscustomobject]@{
            SamAccountName = $m['samAccountName']
            DisplayName    = $g.DisplayName
            GroupScope     = $m['groupScope']
            GroupCategory  = $m['groupCategory']
            MemberCount    = $memberCount
            NestedInGroups = $memberOf.Count
            ParentGroups   = ($memberOf -join '|')
            AdminCount     = $adminCount
            ManagedBy      = $m['managedBy']
            WhenCreated    = $m['whenCreated']
            MemberSample   = $m['memberSample']
            Risk           = $risk
        })
    }

    $arr = @($rows)
    Write-Log "  Total           : $($arr.Count)"
    Write-Log "  Vides (0 membre): $(($arr | Where-Object { $_.MemberCount -eq 0 }).Count)"
    Write-Log "  Admins          : $(($arr | Where-Object { $_.AdminCount -gt 0 }).Count)"
    Write-Log "  Grands (>500)   : $(($arr | Where-Object { $_.MemberCount -gt 500 }).Count)"
    Write-Log "  Imbriqués       : $(($arr | Where-Object { $_.NestedInGroups -gt 0 }).Count)"

    return $arr
}

function ConvertTo-UserAnalysis {
    param($Users, [int]$Threshold)

    Write-Log '=== Analyse des utilisateurs ===' -Level SECTION

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($u in $Users) {
        $m        = $u.Meta
        $memberOf = if ($m.ContainsKey('memberOf') -and $m['memberOf']) {
                        @($m['memberOf'] -split '\|' | Where-Object { $_ })
                    } else { @() }
        $lastLogon = $null
        if ($m.ContainsKey('lastLogonDate') -and $m['lastLogonDate']) {
            try { $lastLogon = [datetime]$m['lastLogonDate'] } catch {}
        }
        $daysSince = if ($lastLogon) {
            ([datetime]::UtcNow - $lastLogon.ToUniversalTime()).Days
        } else { -1 }

        $rows.Add([pscustomobject]@{
            SamAccountName = $m['samAccountName']
            DisplayName    = $u.DisplayName
            Department     = $m['department']
            Company        = $m['company']
            EmployeeType   = $m['employeeType']
            Manager        = $m['manager']
            GroupCount     = $memberOf.Count
            Groups         = ($memberOf -join '|')
            LastLogonDate  = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { '' }
            DaysSinceLogon = $daysSince
            OverPrivileged = ($memberOf.Count -ge $Threshold)
        })
    }

    $arr = @($rows)
    Write-Log "  Total                         : $($arr.Count)"
    Write-Log "  Sur-privilégiés (>= $Threshold groupes): $(($arr | Where-Object { $_.OverPrivileged }).Count)"
    Write-Log "  Sans groupe                   : $(($arr | Where-Object { $_.GroupCount -eq 0 }).Count)"

    $byDept = @($arr | Group-Object Department | Sort-Object Count -Descending)
    Write-Log "  Départements ($($byDept.Count)) — Top 5 :"
    $byDept | Select-Object -First 5 | ForEach-Object {
        Write-Log "    [$($_.Count)] $($_.Name)"
    }

    return $arr
}

function ConvertTo-DelegationAnalysis {
    param($Delegations)

    Write-Log '=== Analyse des délégations ===' -Level SECTION

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($d in $Delegations) {
        $m      = $d.Meta
        $rights = if ($m.ContainsKey('adRights')) { $m['adRights'] } else { '' }
        $risk   = if ($rights -match 'GenericAll|WriteDacl|WriteOwner') { 'Critical' }
                  elseif ($rights -match 'GenericWrite|WriteProperty')  { 'High' }
                  elseif ($rights -match 'CreateChild|DeleteChild|ExtendedRight') { 'Medium' }
                  else { 'Low' }

        $rows.Add([pscustomobject]@{
            OUName           = $m['ouName']
            OUDN             = $m['ouDN']
            Identity         = $m['identity']
            ADRights         = $rights
            AccessType       = $m['accessType']
            ObjectType       = $m['objectTypeName']
            InheritedType    = $m['inheritedTypeName']
            InheritanceFlags = $m['inheritanceFlags']
            Risk             = $risk
        })
    }

    $arr = @($rows)
    Write-Log "  Total     : $($arr.Count)"
    Write-Log "  Critiques : $(($arr | Where-Object { $_.Risk -eq 'Critical' }).Count)  (GenericAll/WriteDacl/WriteOwner)"
    Write-Log "  Hautes    : $(($arr | Where-Object { $_.Risk -eq 'High' }).Count)  (GenericWrite/WriteProperty)"
    Write-Log "  Moyennes  : $(($arr | Where-Object { $_.Risk -eq 'Medium' }).Count)  (CreateChild/DeleteChild)"

    $top5 = @($arr | Group-Object Identity | Sort-Object Count -Descending | Select-Object -First 5)
    Write-Log "  Top 5 identités déléguées :"
    $top5 | ForEach-Object { Write-Log "    [$($_.Count) ACEs] $($_.Name)" }

    return $arr
}

function ConvertTo-ComputerAnalysis {
    param($Computers)

    Write-Log '=== Analyse des ordinateurs ===' -Level SECTION

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($c in $Computers) {
        $m = $c.Meta
        $lastLogon = $null
        if ($m.ContainsKey('lastLogonDate') -and $m['lastLogonDate']) {
            try { $lastLogon = [datetime]$m['lastLogonDate'] } catch {}
        }
        $daysSince = if ($lastLogon) {
            ([datetime]::UtcNow - $lastLogon.ToUniversalTime()).Days
        } else { -1 }

        $rows.Add([pscustomobject]@{
            Name                   = $c.DisplayName
            SamAccountName         = $m['samAccountName']
            DNSHostName            = $m['dnsHostName']
            OperatingSystem        = $m['operatingSystem']
            OperatingSystemVersion = $m['operatingSystemVersion']
            Location               = $m['location']
            ManagedBy              = $m['managedBy']
            LastLogonDate          = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { '' }
            DaysSinceLogon         = $daysSince
            ServicePrincipalNames  = $m['servicePrincipalNames']
        })
    }

    $arr = @($rows)
    Write-Log "  Total : $($arr.Count)"

    $byOS = @($arr | Group-Object OperatingSystem | Sort-Object Count -Descending)
    Write-Log "  Systèmes d'exploitation :"
    $byOS | ForEach-Object { Write-Log "    [$($_.Count)] $($_.Name)" }

    return $arr
}

#endregion

#region --- CARTES DÉRIVÉES ---

function Get-DelegationByOU {
    param($Delegations)
    @($Delegations | Group-Object OUDN | ForEach-Object {
        [pscustomobject]@{
            OUDN          = $_.Name
            OUName        = ($_.Group | Select-Object -First 1).OUName
            ACECount      = $_.Count
            Identities    = (($_.Group | Select-Object -ExpandProperty Identity -Unique) -join '|')
            CriticalCount = ($_.Group | Where-Object { $_.Risk -eq 'Critical' }).Count
            HighCount     = ($_.Group | Where-Object { $_.Risk -eq 'High' }).Count
        }
    } | Sort-Object ACECount -Descending)
}

function Get-DelegationByIdentity {
    param($Delegations)
    @($Delegations | Group-Object Identity | ForEach-Object {
        $ous = @($_.Group | Select-Object -ExpandProperty OUDN -Unique)
        [pscustomobject]@{
            Identity      = $_.Name
            ACECount      = $_.Count
            OUCount       = $ous.Count
            OUs           = ($ous -join '|')
            CriticalCount = ($_.Group | Where-Object { $_.Risk -eq 'Critical' }).Count
            HighCount     = ($_.Group | Where-Object { $_.Risk -eq 'High' }).Count
            Rights        = (($_.Group | Select-Object -ExpandProperty ADRights -Unique) -join '|')
        }
    } | Sort-Object ACECount -Descending)
}

function Get-RBACCandidates {
    <#
    .SYNOPSIS
        Corrèle les groupes aux départements via les appartenances des utilisateurs.
        Un groupe avec une forte couverture d'un département est un bon candidat de rôle.
    #>
    param($Users)

    # Département → groupe → nombre d'utilisateurs du département membres du groupe
    $deptGroups = @{}
    foreach ($u in $Users) {
        $dept = $u.Department
        if (-not $dept -or $u.GroupCount -eq 0) { continue }
        if (-not $deptGroups.ContainsKey($dept)) { $deptGroups[$dept] = @{} }

        $u.Groups -split '\|' | Where-Object { $_ } | ForEach-Object {
            $grp = $_
            if ($deptGroups[$dept].ContainsKey($grp)) {
                $deptGroups[$dept][$grp]++
            } else {
                $deptGroups[$dept][$grp] = 1
            }
        }
    }

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($dept in $deptGroups.Keys) {
        $deptUserCount = ($Users | Where-Object { $_.Department -eq $dept }).Count
        if ($deptUserCount -eq 0) { continue }

        foreach ($grpName in $deptGroups[$dept].Keys) {
            $count    = $deptGroups[$dept][$grpName]
            $coverage = [math]::Round($count / $deptUserCount * 100, 1)
            $rows.Add([pscustomobject]@{
                Department      = $dept
                GroupName       = $grpName
                DeptMemberCount = $count
                DeptTotalUsers  = $deptUserCount
                CoveragePct     = $coverage
                RoleCandidate   = ($coverage -ge 50)
            })
        }
    }

    return @($rows | Where-Object { $_ } | Sort-Object Department, CoveragePct -Descending)
}

#endregion

#region --- EXPORT CSV ---

function Export-AnalysisCSV {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Data,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Log "  Aucune donnée pour '$Name' — fichier non créé." -Level WARN
        return
    }
    $path = Join-Path $AnalysisPath "${Name}_$($Script:Timestamp).csv"
    $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Log "  $Name : $($Data.Count) lignes → $path" -Level SUCCESS
}

#endregion

#region --- POINT D'ENTRÉE ---

function Main {
    if (-not (Test-Path $AnalysisPath)) {
        New-Item -ItemType Directory -Path $AnalysisPath -Force | Out-Null
        Write-Log "Dossier d'analyse créé : $AnalysisPath"
    }

    Write-Log ('=' * 65) -Level SECTION
    Write-Log " Démarrage  : $(Get-Date -Format 'o')" -Level SECTION
    Write-Log " LDS cible  : $($Script:LDSTarget)  BaseDN=$LDSBaseDN" -Level SECTION
    Write-Log " Seuil sur-privilège : $OverPrivilegedThreshold groupes" -Level SECTION
    Write-Log ('=' * 65) -Level SECTION

    # Lecture LDS
    Write-Log 'Lecture des données LDS...'
    $rawUsers       = Read-LDSOUObjects -OUDN "OU=Users,$LDSBaseDN"
    $rawGroups      = Read-LDSOUObjects -OUDN "OU=Groups,$LDSBaseDN"
    $rawComputers   = Read-LDSOUObjects -OUDN "OU=Computers,$LDSBaseDN"
    $rawDelegations = Read-LDSOUObjects -OUDN "OU=Delegations,$LDSBaseDN"

    Write-Log ("Objets lus — Utilisateurs: {0} | Groupes: {1} | Ordinateurs: {2} | Délégations: {3}" -f `
        $rawUsers.Count, $rawGroups.Count, $rawComputers.Count, $rawDelegations.Count)

    # Analyses
    $groups      = ConvertTo-GroupAnalysis      -Groups $rawGroups
    $users       = ConvertTo-UserAnalysis       -Users $rawUsers -Threshold $OverPrivilegedThreshold
    $delegations = ConvertTo-DelegationAnalysis -Delegations $rawDelegations
    $computers   = ConvertTo-ComputerAnalysis   -Computers $rawComputers

    # Cartes dérivées
    $delByOU         = Get-DelegationByOU       -Delegations $delegations
    $delByIdentity   = Get-DelegationByIdentity -Delegations $delegations
    $rbacCandidates  = Get-RBACCandidates       -Users $users

    # Export CSV
    Write-Log '=== Export CSV ===' -Level SECTION
    Export-AnalysisCSV -Data $groups      -Name 'groups'
    Export-AnalysisCSV -Data $users       -Name 'users'
    Export-AnalysisCSV -Data $delegations -Name 'delegations'
    Export-AnalysisCSV -Data $computers   -Name 'computers'
    Export-AnalysisCSV -Data @($groups | Where-Object { $_.MemberCount -eq 0 })                 -Name 'empty-groups'
    Export-AnalysisCSV -Data @($users  | Where-Object { $_.OverPrivileged })                    -Name 'over-privileged-users'
    Export-AnalysisCSV -Data @($delegations | Where-Object { $_.Risk -in 'Critical', 'High' })  -Name 'high-risk-delegations'
    Export-AnalysisCSV -Data $delByOU                                                            -Name 'delegation-by-ou'
    Export-AnalysisCSV -Data $delByIdentity                                                      -Name 'delegation-by-identity'
    Export-AnalysisCSV -Data @($rbacCandidates | Where-Object { $_.RoleCandidate })             -Name 'rbac-candidates'

    # Résumé final
    Write-Log ('=' * 65) -Level SECTION
    Write-Log ' RÉSUMÉ' -Level SECTION
    Write-Log ('=' * 65) -Level SECTION
    Write-Log ("Groupes      — Total: {0,6} | Vides: {1,4} | Admin: {2,4}" -f `
        $groups.Count,
        ($groups | Where-Object { $_.MemberCount -eq 0 }).Count,
        ($groups | Where-Object { $_.AdminCount -gt 0 }).Count)
    Write-Log ("Utilisateurs — Total: {0,6} | Sur-privilégiés (>={1}): {2,4} | Sans groupe: {3,4}" -f `
        $users.Count, $OverPrivilegedThreshold,
        ($users | Where-Object { $_.OverPrivileged }).Count,
        ($users | Where-Object { $_.GroupCount -eq 0 }).Count)
    Write-Log ("Délégations  — Total: {0,6} | Critiques: {1,4} | Hautes: {2,4}" -f `
        $delegations.Count,
        ($delegations | Where-Object { $_.Risk -eq 'Critical' }).Count,
        ($delegations | Where-Object { $_.Risk -eq 'High' }).Count)
    Write-Log ("Ordinateurs  — Total: {0,6}" -f $computers.Count)
    Write-Log ("RBAC candidats identifiés (>= 50%% couverture dept) : {0}" -f `
        ($rbacCandidates | Where-Object { $_.RoleCandidate }).Count)
    Write-Log '---'
    Write-Log "Rapports dans : $AnalysisPath"
    Write-Log "Log           : $LogPath"
    Write-Log 'Analyse terminée.' -Level SUCCESS
}

Main

#endregion
