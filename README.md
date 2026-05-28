# IaRBAC — Identity & Access Role-Based Access Control

Outillage PowerShell pour analyser les rôles et permissions d'un **Active Directory** et construire un modèle **RBAC** et un modèle de **délégation administrative**.

La démarche repose sur une copie filtrée de l'AD vers une instance **AD LDS** (Lightweight Directory Services), servant de référentiel d'analyse sans impacter la production.

## Démarche en 3 étapes

```text
[AD DS] ──(Export-ADToLDS.ps1)──> [AD LDS] ──(Analyze-LDSData.ps1)──> [CSV + docs]
```

### Étape 1 — Exporter l'AD vers LDS

```powershell
.\scripts\Export-ADToLDS.ps1 `
    -LDSServer "lds01.corp.local" `
    -LDSPort 50389 `
    -LDSBaseDN "DC=rbac,DC=corp,DC=local"
```

Crée dans LDS : `OU=Users`, `OU=Groups`, `OU=Computers`, `OU=Delegations`.

### Étape 2 — Analyser les données LDS

```powershell
.\scripts\Analyze-LDSData.ps1 `
    -LDSServer "lds01.corp.local" `
    -LDSPort 50389 `
    -LDSBaseDN "DC=rbac,DC=corp,DC=local"
```

Produit dans `analysis/` :

| Fichier | Contenu |
| --- | --- |
| `groups_*.csv` | Groupes avec comptages et niveau de risque |
| `users_*.csv` | Utilisateurs avec score de privilège |
| `delegations_*.csv` | ACEs avec scoring de risque |
| `computers_*.csv` | Ordinateurs actifs |
| `empty-groups_*.csv` | Groupes sans membres |
| `over-privileged-users_*.csv` | Utilisateurs membres de trop de groupes |
| `high-risk-delegations_*.csv` | GenericAll / WriteDacl / WriteOwner |
| `delegation-by-ou_*.csv` | Carte des droits par OU |
| `delegation-by-identity_*.csv` | Carte des droits par identité |
| `rbac-candidates_*.csv` | Corrélation département ↔ groupes |

### Étape 3 — Compléter les livrables

À partir des rapports CSV, remplir :

- [docs/rbac-model.md](docs/rbac-model.md) — matrice rôle ↔ permissions, plan de migration
- [docs/delegation-model.md](docs/delegation-model.md) — modèle L1/L2/L3, délégations à révoquer/créer

## Prérequis

| Composant | Détail |
| --- | --- |
| PowerShell | 5.1 minimum |
| Module AD | `Install-WindowsFeature RSAT-AD-PowerShell` |
| AD source | Windows Server 2016+, compte en lecture (+ `Read Control` sur les OUs) |
| AD LDS | Instance configurée, compte en écriture |

## Structure du projet

```text
IaRBAC/
├── scripts/
│   ├── Export-ADToLDS.ps1       # Étape 1 : migration AD → LDS
│   └── Analyze-LDSData.ps1      # Étape 2 : analyse RBAC et délégation
├── docs/
│   ├── rbac-model.md            # Livrable : modèle RBAC (à compléter)
│   └── delegation-model.md      # Livrable : modèle de délégation (à compléter)
└── analysis/                    # Rapports CSV générés (non versionnés)
```

Pour la documentation complète des paramètres et prérequis, voir [CLAUDE.md](CLAUDE.md).
