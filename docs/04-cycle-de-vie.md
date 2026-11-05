# Partie 4 — Cycle de vie des secrets

> Un secret non géré finit par fuiter. Ce document couvre les six étapes, avec
> pour chacune : la pratique recommandée, le risque si elle est absente, et
> **ce qui est réellement implémenté dans ce dépôt** (pas seulement recommandé).

## 4.1 Vue d'ensemble

| Étape | Pratique recommandée | Risque si absent | Implémenté ici ? |
|-------|----------------------|------------------|------------------|
| **Création** | Généré automatiquement, jamais tapé à la main, stocké immédiatement dans le gestionnaire | Secret faible ou réutilisé | Oui — `openssl rand` dans `01-deploy-vault-eso.sh`, seed direct dans Vault |
| **Stockage** | Vault **ou** Secret K8s chiffré au repos dans etcd | Exposition si accès à etcd | Oui — Vault (source de vérité) **et** `aescbc` dans etcd (double couche) |
| **Distribution** | Injection par sidecar ou volume monté, jamais en variable d'env du manifest | Exposition dans les logs, `kubectl describe` | Oui — volumes montés, `items` explicites, `0400` |
| **Utilisation** | Lecture seule, jamais loggé, TTL court | Secret longue durée difficile à révoquer | Oui — empreintes seulement dans les logs ; TTL Vault 5 min (dynamic) / 20 min (token ESO) |
| **Rotation** | Automatisée (Vault dynamic secrets ou ESO) | Credentials compromis restent valides | Oui — ESO `refreshInterval: 30s` + rotation démontrée sans redémarrage |
| **Révocation** | Immédiate, sans redéploiement | Fenêtre d'exposition longue après incident | Oui — `vault lease revoke` pour les dynamic secrets ; `ALTER USER` pour le statique |
| **Suppression** | Soft-delete avec rétention, audit de qui a eu accès | Perte de traçabilité | Oui — KV v2 (versions conservées), `deletionPolicy: Retain`, audit device Vault |

## 4.2 Création — l'entropie n'est pas optionnelle

```bash
# Ce qui est fait (scripts/01-deploy-vault-eso.sh)
PG_APP_PASSWORD="$(openssl rand -hex 24)"       # 192 bits
JWT_SIGNING_KEY="$(openssl rand -base64 48)"    # 384 bits
```

Un mot de passe « fort » choisi par un humain a typiquement 30 à 40 bits
d'entropie réelle. 24 octets aléatoires en ont 192. Ce n'est pas de la
coquetterie : c'est la différence entre « cassable hors ligne en quelques
heures » et « hors de portée ».

**Anti-pattern évité** : aucun secret n'est écrit dans un manifest, même
temporairement. Les valeurs passent d'`openssl` à un `Secret` éphémère créé
par `kubectl create secret` (donc jamais dans le dépôt), puis dans Vault.

## 4.3 Stockage — deux couches, pas une

| Couche | Protège contre | Ne protège pas contre |
|--------|----------------|------------------------|
| Vault (chiffrement + policies + audit) | accès non autorisé, absence de traçabilité | compromission du cluster entier |
| Chiffrement etcd `aescbc` | vol de snapshot etcd, accès disque | lecture via l'API par un compte autorisé |
| RBAC | lecture non autorisée via l'API | accès direct à etcd, admin du cluster |
| NetworkPolicy | appel direct au conteneur Vault | trafic east-west non couvert |

Empiler ces couches est le seul moyen de couvrir les scénarios de la partie 6.

## 4.4 Distribution — la chaîne complète

```
Vault (source de vérité)
  |  auth Kubernetes : JWT projeté du SA sa-eso
  v
External Secrets Operator  -- refreshInterval: 30s --+
  |                                                  |
  v                                                  v
Secret K8s (backend/db-credentials)      Secret K8s (database/db-credentials)
  |  volume monté (0400)                             |  variable d'env (limite assumée)
  v                                                  v
api-backend lit le FICHIER à chaque requête      postgres au démarrage
```

Pourquoi ESO plutôt que le Vault Agent Injector : voir le comparatif en
[08-comparaison-approches.md](08-comparaison-approches.md).

## 4.5 Rotation — le point le plus important

### Ce que la démo prouve

`make demo-4-rotation` exécute la séquence complète et affiche un tableau
avant/après. Résultat attendu :

| Témoin | Avant | Après |
|--------|-------|-------|
| Empreinte du mot de passe (vu par l'application) | `a1b2c3d4e5f6` | `9f8e7d6c5b4a` |
| UID du Pod `api-backend` | inchangé | **inchangé** |
| Date de création du Pod | inchangée | **inchangée** |
| `restartCount` du conteneur | 0 | **0** |
| Connexion PostgreSQL | OK | **OK avec le nouveau mot de passe** |

### Le mécanisme, en trois horloges

La rotation n'est pas instantanée ; elle dépend de trois délais qu'il faut
savoir nommer :

| Délai | Valeur typique | Réglable par |
|-------|----------------|--------------|
| Vault → ESO | `refreshInterval` (30 s ici) | `spec.refreshInterval` de l'ExternalSecret |
| ESO → Secret K8s | quasi nul (une écriture API) | — |
| Secret K8s → fichier dans le Pod | **jusqu'à ~60 s** (kubelet sync period) + cache | `--node-status-update-frequency` (non recommandé) |

**Conséquence honnête** : une rotation prend 30 à 90 secondes. Ce n'est pas
zéro. Si l'on veut une fenêtre réellement nulle, il faut que le consommateur
demande le credential **au moment de l'utiliser** : c'est le rôle des
*dynamic secrets* (Vault génère un utilisateur PostgreSQL jetable à chaque
demande, TTL 5 min, `DROP ROLE` automatique à l'expiration).

### Pourquoi ça marche sans redémarrage

Parce que l'application **relit le fichier à chaque requête** (aucun cache) et
que le kubelet met à jour le contenu du volume monté quand le Secret change.
Les deux conditions sont nécessaires : une application qui lit son secret une
fois au démarrage (ou qui le met en variable d'environnement) ne bénéficiera
jamais de la rotation, même avec ESO correctement configuré.

## 4.6 Révocation — la seule action qui protège vraiment

Après une fuite, l'ordre des opérations compte :

1. **Révoquer** le credential (Vault, `ALTER USER`, fournisseur d'API).
2. **Faire tourner** immédiatement (démo 4).
3. **Chercher** l'usage du credential dans les logs (audit log K8s + audit Vault).
4. **Seulement ensuite** nettoyer l'historique Git — et considérer que la
   valeur a fuité de toute façon.

L'inverse (nettoyer Git d'abord) est l'erreur classique : pendant le nettoyage,
le credential reste valide et utilisé.

## 4.7 Suppression — garder la trace

| Mécanisme | Réglage | Effet |
|-----------|---------|-------|
| KV v2 (Vault) | par défaut | Les anciennes versions restent accessibles (audit possible), `metadata` supprimable séparément |
| `deletionPolicy: Retain` | sur `database/db-credentials` | Si l'ExternalSecret disparaît, la base ne perd pas son mot de passe en production |
| `deletionPolicy: Delete` (défaut ESO) | sur `backend/*` | Le Secret suit la vie de l'ExternalSecret : pas de secret orphelin |
| `ttlSecondsAfterFinished` | Jobs de démo | Pas d'accumulation de Pods terminés |
| Audit | `audit-policy.yaml` + audit Vault | Post-mortem : qui a lu quoi, quand |

## 4.8 Ce qui n'est pas implémenté (et qu'il faut dire)

| Point | Statut | Pourquoi / que faire |
|-------|--------|----------------------|
| Rotation du mot de passe `postgres` superutilisateur | Semi-manuelle (`ALTER USER` dans le script) | PostgreSQL ne relit pas son mot de passe à chaud ; utiliser des dynamic secrets pour les rôles applicatifs |
| Rotation de la clé de chiffrement etcd | Procédure documentée, non automatisée | `automatic-reload` + réécriture de tous les secrets |
| cert-manager / ACME pour S5 | Hors périmètre du lab | Ajouter cert-manager + un `Certificate` + `Ingress` |
| OIDC CI/CD (S6) | Documenté, non déployé | Configurer l'OIDC GitHub/GitLab vers Vault `jwt` auth, pas de token statique |
| Rotation de la clé JWT avec chevauchement | Non implémentée | Publier un `kid` + accepter 2 clés pendant 24 h |
