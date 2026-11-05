# Partie 5 — HashiCorp Vault et External Secrets Operator

> Vault résout les limites des Secrets Kubernetes natifs : chiffrement
> centralisé, rotation automatique, audit complet, TTL par secret.
> **Recommandation retenue pour ce projet : External Secrets Operator.**

## 5.1 Les trois approches d'intégration

| Approche | Mécanisme | Avantages | Inconvénients | Verdict |
|----------|-----------|-----------|---------------|---------|
| **Secrets Kubernetes natifs** | etcd + RBAC + chiffrement au repos | Simple, natif, zéro dépendance | Pas de rotation auto, chiffrement limité, audit pauvre | Base indispensable, insuffisant seul |
| **Vault Agent Injector** | Sidecar injecté par webhook mutating | Le secret n'est **jamais** dans etcd ; rotation transparente ; rendu de templates | Complexité opérationnelle ; Vault = SPOF ; un sidecar par Pod | Le plus sûr, le plus lourd |
| **External Secrets Operator** | Opérateur qui synchronise Vault → Secret K8s | Familier pour les équipes K8s, compatible GitOps, un seul déploiement | Le secret **est** dans etcd (chiffré), synchronisation avec délai | **Retenu** |

### Pourquoi ESO pour ce projet

1. **Niveau intermédiaire** : il apporte l'essentiel (source de vérité
   centralisée, rotation, audit) sans imposer un sidecar par Pod.
2. **GitOps-compatible** : un `ExternalSecret` est un manifest déclaratif
   versionnable — il ne contient aucune valeur, seulement une référence. C'est
   exactement le pattern attendu dans un dépôt.
3. **Démonstration lisible** : la rotation se voit (`status.refreshTime`, UID
   du Pod inchangé), ce qui compte pour une soutenance.
4. **Réversible** : passer à l'Agent Injector plus tard ne change ni Vault ni
   les politiques, seulement la couche de distribution.

Ce qui est perdu par rapport à l'Agent Injector : le secret transite et réside
dans etcd. C'est acceptable **parce que** le chiffrement `aescbc` est actif
(partie 2) — les deux décisions sont liées, pas indépendantes.

## 5.2 Architecture déployée

```
                       +--------------------------+
                       |   Vault (ns vault)       |
                       |   - KV v2 : secret/      |
                       |   - database/ (dynamic)  |
                       |   - auth/kubernetes      |
                       |   - policy eso-policy    |
                       |   - audit device (file)  |
                       +------------+-------------+
                                    ^
             JWT du SA sa-eso       |  HTTP 8200 (réseau interne)
             validé par TokenReview |
                       +------------+-------------+
                       | ESO (ns external-secrets)|
                       | ClusterSecretStore       |
                       |  vault-backend           |
                       +------+-------------+-----+
                              |             |
                  Secret K8s  |             |  Secret K8s
              backend/        |             |  database/
              db-credentials  |             |  db-credentials
                              v             v
                        api-backend     postgres
```

## 5.3 Ce qui est installé et configuré

| Élément | Fichier | Rôle |
|---------|---------|------|
| Vault en mode dev | `infrastructure/vault/vault-dev.yaml` | Serveur Vault (mémoire, unsealed) |
| RBAC d'authentification | `infrastructure/vault/vault-auth-rbac.yaml` | SA `vault-auth` + `system:auth-delegator` |
| Politique ESO | `infrastructure/vault/policies/eso-policy.hcl` | Lecture seule des chemins nécessaires |
| Script de bootstrap | `infrastructure/vault/bootstrap-script-configmap.yaml` | Idempotent : auth K8s, moteur DB, seed KV, policy |
| Job de bootstrap | `infrastructure/vault/bootstrap-job.yaml` | Exécute le script avec un JWT d'audience `vault` |
| ClusterSecretStore | `infrastructure/eso/cluster-secret-store.yaml` | Pont restreint par `conditions` |
| ExternalSecrets | `infrastructure/eso/externalsecrets.yaml` | 4 déclarations (backend ×3, database ×1) |
| Dynamic secrets (option) | `infrastructure/eso/externalsecret-dynamic.yaml` | Credentials PostgreSQL jetables, TTL 5 min |

## 5.4 Le bootstrap, expliqué

Le script `bootstrap.sh` fait, dans l'ordre :

1. **Audit device** (`file`, `/vault/audit/audit.log`) — toute lecture de
   secret est tracée avec l'identité du demandeur.
2. **KV v2** sur `secret/` — versionnement natif : une rotation crée une
   version N+1, l'ancienne reste consultable (post-mortem).
3. **Moteur `database`** connecté à PostgreSQL — permet de créer des rôles
   jetables *à l'intérieur* de la base.
4. **Rôle `app`** (dynamic secrets) : `default_ttl=5m`, `max_ttl=15m`,
   `creation_statements` qui font un `CREATE ROLE ... VALID UNTIL ...` et un
   `revocation_statements` qui font un `DROP ROLE` — la révocation est donc
   automatique à l'expiration du lease.
5. **Seed KV** : `secret/backend/db-credentials`, `secret/database/db-credentials`,
   `secret/backend/jwt-key`, `secret/backend/external-api-key`.
6. **`auth/kubernetes`** : Vault valide les JWT via TokenReview, avec la CA du
   cluster et le token reviewer du SA `vault-auth`.
7. **Rôle `auth/kubernetes/role/eso`** : `bound_service_account_names=sa-eso`,
   `bound_service_account_namespaces=external-secrets`,
   `bound_audiences=vault`, `token_policies=eso-policy`, `token_ttl=20m`.

Le point 7 est le contrôle le plus important : **même si un attaquant obtient
un JWT valide d'un autre ServiceAccount, Vault le refuse** car le nom ET le
namespace doivent correspondre. C'est une authentification à double critère,
pas un simple token.

## 5.5 Dynamic secrets — la vraie réponse à la limite du statique

Un secret statique est un secret compromis en attente. Les dynamic secrets
suppriment le problème à la racine :

```bash
# Vault crée un utilisateur PostgreSQL jetable, TTL 5 min
vault read database/creds/app
# Key                Value
# lease_id           database/creds/app/xxxx
# lease_duration     5m
# username           v-kubernetes-app-x7k2p9
# password           A1b2C3d4E5...
```

À l'expiration du lease, Vault exécute `DROP ROLE` : le credential n'existe
plus. Un attaquant qui vole ce mot de passe a une fenêtre de 5 minutes, et
seulement pour un rôle non superutilisateur.

**Activation dans le lab** :

```bash
kubectl apply -f infrastructure/eso/externalsecret-dynamic.yaml
kubectl -n backend get secret db-dynamic-credentials -o jsonpath='{.data.username}' | base64 -d
# v-kubernetes-app-xxxxx  -> un utilisateur différent à chaque synchronisation
```

**Limite à énoncer** : avec un TTL de 5 minutes et un `refreshInterval` de
60 s, une application qui garde une **connexion persistante** (pool) reste
authentifiée jusqu'à la fin de la connexion — PostgreSQL ne coupe pas les
sessions existantes à l'expiration du rôle. Il faut donc :
soit un pool qui recycle les connexions plus vite que le TTL, soit accepter
une fenêtre résiduelle. C'est une nuance que peu de présentations mentionnent,
et c'est exactement ce qu'un jury attend.

## 5.6 La nouvelle surface d'attaque : Vault lui-même

| Risque | Impact | Contre-mesure |
|--------|--------|---------------|
| Vol du token root | Tous les secrets, tous les namespaces | Token root à usage unique, révoqué après bootstrap ; en prod : pas de token root du tout (Terraform + approle) |
| Vol de la clé d'unseal | Déchiffrement du stockage Vault | Shamir 3/5 (3 parts sur 5 requises), parts chez des personnes différentes ; ou auto-unseal KMS |
| Compromission du Pod Vault | Accès à la mémoire, donc aux secrets déchiffrés | NetworkPolicy (seul ESO entre), `runAsNonRoot`, pas de `automountServiceAccountToken`, stockage chiffré |
| Suppression du PVC Vault | Perte totale des secrets (déni de service) | Sauvegardes chiffrées, snapshots Raft, `deletionPolicy: Retain` |
| Politique trop large | Un client lit des secrets hors périmètre | `eso-policy` avec `deny` explicites sur `sys/*`, `auth/token/*`, `prod-*` |

**Vault est un point unique de défaillance.** C'est le prix de la
centralisation : un seul endroit à protéger (bien) plutôt que N secrets
dispersés (mal). Sur un cluster de production, Vault doit être en HA (Raft
3 nœuds) — ce qui n'est pas le cas ici, en mode dev.

## 5.7 Mode dev : ce qui est simulé

| Aspect | Mode dev (lab) | Production |
|--------|----------------|------------|
| Stockage | mémoire (perdu au redémarrage) | Raft + PVC, sauvegardé |
| Scellement | automatique | manuel (Shamir) ou KMS |
| Token root | `root`, connu | jamais de token root persistant |
| TLS | HTTP en clair | TLS obligatoire, `tls_disable=false` |
| HA | 1 replica | 3 replicas + service actif/standby |
| Audit | fichier local | syslog / stdout → SIEM |

Le mode dev permet de démontrer le **cycle de vie** sans passer trois heures
sur l'initialisation. C'est un choix de périmètre, explicitement assumé.
