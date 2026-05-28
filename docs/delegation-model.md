# Modèle de délégation administrative — [Nom du domaine AD]

> **Statut :** À compléter après analyse  
> **Date :** [À renseigner]  
> **Analyste :** [À renseigner]  
> **Source :** Instance AD LDS générée par `Export-ADToLDS.ps1` + rapports `Analyze-LDSData.ps1`

---

## 1. Contexte

| Champ | Valeur |
| --- | --- |
| Domaine AD source | |
| Nombre d'OUs analysées | |
| Nombre d'ACEs explicites | |
| Délégations critiques | |
| Date d'extraction | |

**Objectif :**  
Cartographier les délégations administratives existantes et proposer un modèle standardisé
par niveau (L1/L2/L3) pour gouverner les droits d'administration délégués sur les OUs.

---

## 2. Inventaire des délégations existantes

### 2.1 Carte des délégations par OU

> Source : `analysis/delegation-by-ou_*.csv` (trié par `ACECount` décroissant)

| OU | Nb ACEs | Identités déléguées | Risque max |
| --- | --- | --- | --- |
| | | | |

### 2.2 Carte des délégations par identité

> Source : `analysis/delegation-by-identity_*.csv`

| Identité | Nb ACEs | Nb OUs | Droits principaux | Risque |
| --- | --- | --- | --- | --- |
| | | | | |

### 2.3 Délégations à risque élevé

> Source : `analysis/high-risk-delegations_*.csv` (Risk = Critical ou High)

| OU | Identité | Droits | Risque | Action recommandée |
| --- | --- | --- | --- | --- |
| | | GenericAll | Critical | Restreindre / justifier |

---

## 3. Modèle de délégation cible

### 3.1 Définition des niveaux

| Niveau | Nom | Description | Périmètre type |
| --- | --- | --- | --- |
| L1 | Helpdesk | Réinitialisation MDP, déverrouillage comptes | OUs utilisateurs opérationnels |
| L2 | Support avancé | Gestion utilisateurs / groupes, attribution licences | OUs métier |
| L3 | Admin domaine | Administration complète, GPO, structure OU | Domaine entier |

### 3.2 Matrice L1 — Helpdesk

| Droit délégué | Objet cible | OUs concernées | Groupe délégué |
| --- | --- | --- | --- |
| Reset Password | user | | |
| Unlock Account (lockoutTime) | user | | |
| Read user attributes | user | | |

### 3.3 Matrice L2 — Support avancé

| Droit délégué | Objet cible | OUs concernées | Groupe délégué |
| --- | --- | --- | --- |
| Create / Delete user | user | | |
| Manage group membership | group | | |
| Modify user attributes | user | | |
| Enable / Disable account | user | | |

### 3.4 Matrice L3 — Admin domaine

| Droit délégué | Objet cible | OUs concernées | Groupe délégué |
| --- | --- | --- | --- |
| Full Control | All objects | Domaine entier | |
| Manage GPO links | | | |
| Create / Delete OU | organizationalUnit | | |
| Manage computer objects | computer | | |

---

## 4. Délégations à révoquer

> Délégations existantes hors modèle cible ou non justifiées.  
> Source : `analysis/high-risk-delegations_*.csv` + revue manuelle de `analysis/delegation-by-identity_*.csv`

| OU | Identité | Droits actuels | Raison de révocation | Remplacement |
| --- | --- | --- | --- | --- |
| | | | Hors modèle | |

---

## 5. Délégations à créer

> Délégations manquantes pour implémenter le modèle cible.

| OU | Identité | Droits à accorder | Niveau | Priorité |
| --- | --- | --- | --- | --- |
| | | | L1 | |

---

## 6. Recommandations

1. **Supprimer les GenericAll non justifiés** : chaque entrée `Critical` de `high-risk-delegations_*.csv` doit avoir une justification ou être révoquée
2. **Standardiser les groupes de délégation** : convention `GRP-DEL-<Niveau>-<OU>` (ex. `GRP-DEL-L1-Users-Paris`)
3. **Documenter les délégations** : associer un ticket / une justification métier à chaque ACE dans la CMDB
4. **Révision annuelle** : ré-exécuter `Export-ADToLDS.ps1 -SkipUsers -SkipGroups -SkipComputers` + `Analyze-LDSData.ps1` pour détecter les dérives
5. **Supprimer les délégations orphelines** : identités dont le compte/groupe n'existe plus dans l'AD (SID non résolu dans les ACLs)

---

## 7. Plan de mise en oeuvre

| Étape | Action | Responsable | Échéance | Statut |
| --- | --- | --- | --- | --- |
| 1 | Valider le modèle L1/L2/L3 avec l'équipe sécurité | | | |
| 2 | Créer les groupes de délégation standardisés | | | |
| 3 | Appliquer le modèle cible sur les OUs pilotes | | | |
| 4 | Révoquer les anciennes délégations | | | |
| 5 | Déployer sur l'ensemble du domaine | | | |
| 6 | Audit ACL post-migration | | | |
