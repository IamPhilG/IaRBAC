# Modèle RBAC — [Nom du domaine AD]

> **Statut :** À compléter après analyse  
> **Date :** [À renseigner]  
> **Analyste :** [À renseigner]  
> **Source :** Instance AD LDS générée par `Export-ADToLDS.ps1` + rapports `Analyze-LDSData.ps1`

---

## 1. Périmètre

| Champ | Valeur |
| --- | --- |
| Domaine AD source | |
| BaseDN LDS | |
| Date d'extraction | |
| Seuil d'inactivité utilisé | jours |
| Utilisateurs analysés | |
| Groupes de sécurité | |
| OUs analysées | |

**Objectif :**  
Construire un modèle RBAC cible qui rationalise les accès existants en regroupant les permissions
communes en rôles explicites, associés aux fonctions métier identifiées dans l'AD.

---

## 2. Inventaire des rôles identifiés

> Remplir à partir de `analysis/rbac-candidates_*.csv` (couverture >= 50 %) et `analysis/groups_*.csv`.  
> Un rôle = ensemble cohérent de permissions couvrant une fonction métier ou technique.

### 2.1 Rôles métier

| ID Rôle | Nom du rôle | Fonction couverte | Groupes AD sources | Membres estimés |
| --- | --- | --- | --- | --- |
| ROLE-M001 | | | | |

### 2.2 Rôles techniques / infrastructure

| ID Rôle | Nom du rôle | Système / ressource | Groupes AD sources | Membres estimés |
| --- | --- | --- | --- | --- |
| ROLE-T001 | | | | |

### 2.3 Rôles administrateurs

> Source : `analysis/groups_*.csv` filtrés sur `AdminCount > 0`

| ID Rôle | Nom du rôle | Périmètre admin | Groupes AD sources | Membres estimés |
| --- | --- | --- | --- | --- |
| ROLE-A001 | | | | |

---

## 3. Matrice rôle ↔ permissions

> Pour chaque rôle, lister les permissions / ressources associées.

| ID Rôle | Nom | Ressources | Permissions | Risque |
| --- | --- | --- | --- | --- |
| | | | | |

---

## 4. Affectation rôles ↔ fonctions

> Associer chaque rôle aux postes / fonctions AD (`title`, `department`).

| Fonction / Département | Rôles attribués | Conditions d'attribution |
| --- | --- | --- |
| | | |

---

## 5. Rôles composites

> Un rôle composite regroupe plusieurs rôles de base (imbrication de groupes existants).  
> Source : `analysis/groups_*.csv` colonne `NestedInGroups > 0`.

| Rôle composite | Rôles inclus | Justification |
| --- | --- | --- |
| | | |

---

## 6. Groupes candidats à la suppression

> Source : `analysis/empty-groups_*.csv` (groupes avec `MemberCount = 0`)

| Groupe AD | Scope | Date création | Action recommandée |
| --- | --- | --- | --- |
| | | | Supprimer / archiver |

---

## 7. Utilisateurs sur-privilégiés

> Source : `analysis/over-privileged-users_*.csv`

| Utilisateur | Département | Nb groupes | Groupes à révoquer | Priorité |
| --- | --- | --- | --- | --- |
| | | | | |

---

## 8. Recommandations

1. **Rationalisation des groupes** : fusionner les groupes redondants identifiés dans `rbac-candidates_*.csv`
2. **Standardisation des noms** : adopter une convention `GRP-<DOMAINE>-<ROLE>-<RW|RO>` (ex. `GRP-FIN-Comptabilite-RW`)
3. **Suppression des groupes vides** : traiter la liste `empty-groups_*.csv` par vague
4. **Revue des sur-privilégiés** : interview des managers des utilisateurs listés dans `over-privileged-users_*.csv`
5. **Revue périodique** : planifier une analyse trimestrielle avec `Analyze-LDSData.ps1`

---

## 9. Plan de migration

| Étape | Action | Responsable | Échéance | Statut |
| --- | --- | --- | --- | --- |
| 1 | Valider le modèle avec les responsables métier | | | |
| 2 | Créer les nouveaux groupes de rôles | | | |
| 3 | Migrer les membres (vague pilote) | | | |
| 4 | Révoquer les anciens groupes | | | |
| 5 | Audit post-migration | | | |
