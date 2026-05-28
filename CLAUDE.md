# IARBAC — Identity & Access Role-Based Access Control

## Objectif

Ce projet outille l'analyse des rôles et permissions d'un Active Directory en vue de :

- Construire un **modèle RBAC** (Role-Based Access Control) fidèle à l'existant
- Modéliser la **délégation administrative** (qui peut faire quoi, sur quoi)
- Produire les données nécessaires à une **refonte des accès** et à une gouvernance des identités

La démarche repose sur une copie filtrée de l'AD vers une instance **AD LDS** (Lightweight Directory Services), qui sert de référentiel d'analyse sans impacter la production.

---

## Structure du projet

```text
IARBAC/
├── CLAUDE.md                    # Ce fichier
├── scripts/
│   └── Export-ADToLDS.ps1       # Migration AD → LDS (utilisateurs, groupes, ordinateurs, délégations)
├── docs/
│   ├── rbac-model.md            # Modèle RBAC cible (à rédiger après analyse)
│   └── delegation-model.md      # Modèle de délégation (à rédiger après analyse)
└── analysis/
    └── (rapports CSV générés par le script)
```

---

## Prérequis

### Environnement source (AD DS)

- Windows Server 2016+ avec le rôle **Active Directory Domain Services**
- Compte avec droits en **lecture sur l'annuaire** et accès aux ACL des OUs (`Read Control` sur les objets)
- Module PowerShell **ActiveDirectory** installé :

  ```powershell
  Install-WindowsFeature RSAT-AD-PowerShell
  ```

### Environnement cible (AD LDS)

- Windows Server avec le rôle **Active Directory Lightweight Directory Services (AD LDS)** installé
- Instance LDS créée (via `adaminstall` ou la console ADSI Edit)
- Port LDAP configuré (ex. 50389 pour éviter les conflits avec l'AD)
- Compte avec droits d'écriture sur l'instance LDS

### Extension du schéma LDS (recommandé)

Par défaut, le schéma LDS est limité (inetOrgPerson, organizationalUnit). Pour stocker des objets
de type `user`, `group`, `computer` natifs, importer les fichiers LDF fournis avec Windows Server :

```cmd
REM Remplacer DC=rbac,DC=corp,DC=local par votre BaseDN LDS
ldifde -i -u -f "C:\Windows\ADAM\MS-AdamSyncMetadata.ldf" ^
       -s localhost:50389 -j . -c "DC=X" "DC=rbac,DC=corp,DC=local"

ldifde -i -u -f "C:\Windows\ADAM\MS-User.ldf" ^
       -s localhost:50389 -j . -c "DC=X" "DC=rbac,DC=corp,DC=local"
```

> **Note :** Le script `Export-ADToLDS.ps1` utilise `inetOrgPerson` (disponible dans le schéma LDS
> par défaut) avec les métadonnées étendues sérialisées en JSON dans le champ `description`.
> L'extension de schéma n'est donc pas obligatoire pour exécuter le script.

---

## Utilisation du script

### Cas minimal

```powershell
.\scripts\Export-ADToLDS.ps1 `
    -LDSServer "lds01.corp.local" `
    -LDSPort 50389 `
    -LDSBaseDN "DC=rbac,DC=corp,DC=local"
```

### Cas complet avec options

```powershell
.\scripts\Export-ADToLDS.ps1 `
    -LDSServer "lds01.corp.local" `
    -LDSPort 50389 `
    -LDSBaseDN "DC=rbac,DC=corp,DC=local" `
    -ADSearchBase "OU=Corp,DC=corp,DC=local" `
    -InactivityThresholdDays 90 `
    -LDSCredential (Get-Credential) `
    -LogPath "C:\Logs\ad-migration.log" `
    -ReportPath "C:\Logs\ad-migration-report.csv"
```

### Simulation (WhatIf)

```powershell
.\scripts\Export-ADToLDS.ps1 -LDSServer "lds01" -LDSPort 50389 `
    -LDSBaseDN "DC=rbac,DC=corp,DC=local" -WhatIf
```

### Export partiel

```powershell
# Exporter uniquement les utilisateurs et groupes, sans ordinateurs ni délégations
.\scripts\Export-ADToLDS.ps1 ... -SkipComputers -SkipDelegations
```

---

## Structure créée dans LDS

```text
DC=rbac,DC=corp,DC=local          ← LDSBaseDN (doit exister avant l'exécution)
├── OU=Users                       ← Utilisateurs actifs (inetOrgPerson)
├── OU=Groups                      ← Groupes de sécurité (inetOrgPerson + métadonnées JSON)
├── OU=Computers                   ← Ordinateurs actifs (inetOrgPerson + métadonnées JSON)
└── OU=Delegations                 ← ACEs de délégation explicites par OU (inetOrgPerson + JSON)
```

Chaque objet LDS stocke ses métadonnées étendues dans l'attribut `description` au format JSON :

**Exemple utilisateur :**

```json
{
  "objectType": "user",
  "samAccountName": "jdupont",
  "upn": "jdupont@corp.local",
  "department": "DSI",
  "lastLogonDate": "2025-11-15T08:32:00Z",
  "adDN": "CN=Jean Dupont,OU=Users,DC=corp,DC=local",
  "memberOf": "GRP-DSI-Admin|GRP-VPN-Users"
}
```

**Exemple délégation :**

```json
{
  "objectType": "delegation",
  "ouDN": "OU=Helpdesk,DC=corp,DC=local",
  "identity": "CORP\\GRP-Helpdesk-Admins",
  "adRights": "WriteProperty, ReadProperty",
  "accessType": "Allow",
  "objectTypeName": "User-Force-Change-Password",
  "inheritedTypeName": "user"
}
```

---

## Workflow d'analyse RBAC

1. **Exécuter le script** → popule l'instance LDS
2. **Interroger LDS** avec ADSI Edit ou des requêtes LDAP pour :
   - Identifier les groupes redondants ou peu utilisés (`memberCount = 0`)
   - Lister les utilisateurs membres de nombreux groupes (sur-privilégiés)
   - Cartographier les délégations par OU et par identité
3. **Construire le modèle RBAC** :
   - Regrouper les permissions communes → définir des **rôles**
   - Associer les rôles aux postes/fonctions identifiés en AD (`title`, `department`)
   - Identifier les rôles composites (rôle contenant d'autres rôles)
4. **Modéliser la délégation** :
   - Lister les ACEs par OU → qui a quoi sur quoi
   - Identifier les délégations héritées vs explicites
   - Proposer un modèle de délégation standardisé par niveau (L1, L2, L3)
5. **Produire les livrables** :
   - `docs/rbac-model.md` : matrice rôle ↔ permissions
   - `docs/delegation-model.md` : modèle de délégation administrative

---

## Fichiers générés

| Fichier | Contenu |
| --- | --- |
| `AD-LDS-Migration_YYYYMMDD_HHmmss.log` | Journal détaillé de l'exécution |
| `AD-LDS-Migration_Report_YYYYMMDD_HHmmss.csv` | Rapport CSV : objet, statut, DN source/cible |

---

## Paramètres du script

| Paramètre | Obligatoire | Défaut | Description |
| --- | --- | --- | --- |
| `LDSServer` | Oui | — | Hôte du serveur LDS |
| `LDSPort` | Non | 389 | Port LDAP LDS |
| `LDSBaseDN` | Oui | — | DN de base de l'instance LDS |
| `ADSearchBase` | Non | Domaine entier | OU de départ pour la recherche AD |
| `InactivityThresholdDays` | Non | 180 | Seuil d'inactivité en jours |
| `LDSCredential` | Non | Identité courante | Credentials LDS |
| `LogPath` | Non | Dossier courant | Chemin du fichier de log |
| `ReportPath` | Non | Dossier courant | Chemin du rapport CSV |
| `SkipUsers` | Non | `$false` | Ne pas exporter les utilisateurs |
| `SkipGroups` | Non | `$false` | Ne pas exporter les groupes |
| `SkipComputers` | Non | `$false` | Ne pas exporter les ordinateurs |
| `SkipDelegations` | Non | `$false` | Ne pas exporter les délégations |
