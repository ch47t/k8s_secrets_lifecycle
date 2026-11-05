# Partie 7 — Comparaison des approches et réponse argumentée

## 7.1 Tableau comparatif (Secret natif / Vault Agent / ESO)

| Critère | Secrets Kubernetes natifs | Vault Agent Injector | External Secrets Operator |
|---------|---------------------------|----------------------|---------------------------|
| **Mécanisme** | etcd + RBAC + `EncryptionConfiguration` | Sidecar injecté par webhook, rendu de fichiers depuis Vault | Opérateur qui synchronise Vault → `Secret` K8s |
| **Le secret passe-t-il par etcd ?** | Oui, toujours | **Non** | Oui, mais chiffré (`aescbc`) |
| **Rotation automatique** | Non (native) | Oui, transparente | Oui, avec délai (`refreshInterval`) |
| **Délai de rotation** | — | ~immédiat (renouvellement du lease) | 30–90 s (ESO + kubelet) |
| **Complexité de déploiement** | Très faible | Élevée (webhook, sidecar, annotations par Pod) | Moyenne (1 opérateur + CRDs) |
| **Complexité opérationnelle** | Faible | Élevée (un sidecar par Pod, debug difficile) | Moyenne |
| **Audit** | Pauvre (audit K8s seulement) | Complet (audit Vault) | Complet (audit Vault) + audit K8s |
| **GitOps** | Naturel (mais risque de commit) | Annotations dans les manifests | Naturel : `ExternalSecret` = référence, aucune valeur |
| **Vault = SPOF ?** | Non | **Oui** (chaque Pod dépend de Vault au démarrage) | Oui, mais les Secrets sont déjà synchronisés : un Vault indisponible ne casse pas les Pods existants |
| **Impact sur les Pods** | Aucun | 1 conteneur supplémentaire par Pod | Aucun |
| **Sécurité de la valeur** | Dans etcd (chiffré si configuré) | Jamais persistée sur disque | Dans etcd (chiffré) |
| **Cas d'usage idéal** | Petits clusters, secrets peu sensibles | Secrets très sensibles, rotation continue | Équipes K8s, migration progressive |

### Exemple concret pour chacun

| Approche | Exemple dans ce lab |
|----------|---------------------|
| **Natif** | `POSTGRES_PASSWORD` lu via `secretKeyRef` dans `apps/database/postgres.yaml` — un Secret chiffré dans etcd, mais figé au démarrage du Pod |
| **Agent Injector** | *(non déployé)* annotation `vault.hashicorp.com/agent-inject: "true"` sur le Pod `api-backend` ; le secret serait écrit dans `/vault/secrets/` par le sidecar, jamais dans etcd |
| **ESO** | `ExternalSecret db-credentials` dans `backend` → Secret K8s → volume monté dans `api-backend` (rotation démontrée, démo 4) |

## 7.2 Pourquoi ESO pour ce projet

1. **Niveau intermédiaire demandé par le plan** : rotation et audit
   centralisés, sans la complexité opérationnelle de l'Agent Injector.
2. **Modèle mental des équipes K8s** : un `ExternalSecret` est un manifest
   comme un autre — lisible, relu en revue de code, compatible Argo CD/Flux.
3. **Aucune valeur dans le dépôt** : l'`ExternalSecret` ne contient qu'un
   chemin Vault et un nom de clé. Le dépôt peut être public.
4. **Réversibilité** : passer à l'Agent Injector ne demande pas de changer
   Vault ni les politiques, seulement la distribution.
5. **Démonstrabilité** : la rotation est observable (`status.refreshTime`,
   UID du Pod inchangé), ce qui compte pour une soutenance.

## 7.3 Ce que l'on paie en choisissant ESO

| Coût | Détail | Mitigation dans ce projet |
|------|--------|---------------------------|
| Le secret réside dans etcd | Contrairement à l'Agent Injector | `aescbc` actif dès la création du cluster — les deux choix sont liés |
| Délai de synchronisation | 30–90 s entre Vault et le Pod | `refreshInterval: 30s` ; dynamic secrets pour une fenêtre nulle |
| ESO est un composant privilégié | Il écrit dans les Secrets de plusieurs namespaces | `ClusterSecretStore` restreint par `conditions` ; politique Vault en lecture seule |
| Un CRD de plus à maintenir | Versionnage d'ESO | Chart Helm épinglé, CRDs via `installCRDs` |

## 7.4 Réponse argumentée à la question centrale

> **Comment garantir que seuls les workloads et les utilisateurs autorisés
> peuvent accéder aux secrets nécessaires à leur fonctionnement ?**

La réponse tient en quatre principes articulés, et non en une seule technologie.

### Principe 1 — Identifier avant de protéger

On ne peut pas sécuriser ce qu'on n'a pas listé. La [matrice des secrets](01-matrice-secrets.md)
est le point de départ obligatoire : chaque secret a un propriétaire, un
consommateur, une durée de vie et un niveau de sensibilité. Sans cette
matrice, les choix techniques des parties 2 à 5 sont arbitraires.

*Preuve dans le projet* : 11 secrets identifiés (S1–S11), dont 5 hors cluster
(S9–S11) qui n'auraient jamais été protégés par du RBAC.

### Principe 2 — Moindre privilège appliqué au RBAC

Un workload ne reçoit l'accès qu'aux secrets dont il a **strictement** besoin,
nommés explicitement dans `resourceNames`. L'absence de `resourceNames` est la
première erreur de configuration à éviter — et `list`/`watch` sont à proscrire
car ils contournent ce filtrage.

*Preuve* : `sa-backend` → `get` sur 2 secrets nommés ; `sa-frontend` → rien ;
aucun `ClusterRole` sur les secrets ; `make validate` vérifie mécaniquement
l'absence de `list`/`watch`.

### Principe 3 — Ne jamais stocker un secret là où il n'est pas chiffré

Ni dans Git, ni dans une variable d'environnement de manifest, ni dans etcd
sans `EncryptionConfiguration`. Le chiffrement au repos dans etcd est un
prérequis non négociable : le RBAC protège l'API, pas le stockage.

*Preuve* : `aescbc` actif dès la création du cluster, clé hors du cluster et
gitignorée, `identity` uniquement en lecture de migration, gitleaks en
pre-commit.

### Principe 4 — Automatiser la rotation pour supprimer la fenêtre d'exposition

Un secret statique est un secret compromis en attente. Vault avec ses dynamic
secrets supprime le problème à la racine : les credentials ont une durée de
vie courte (5 min) et sont révocables instantanément (`DROP ROLE`).

*Preuve* : démo 4 (rotation sans redémarrage), `externalsecret-dynamic.yaml`
(utilisateur PostgreSQL jetable).

### Et une couche que les quatre principes n'impliquent pas : le réseau

Le RBAC dit « qui peut lire quoi dans l'API ». Il ne dit rien du trafic. Sans
`NetworkPolicy`, un Pod compromis interroge Vault directement. C'est pourquoi
le projet ajoute une couche d'isolation réseau et la démontre par la preuve
(test de contrôle + test négatif).

## 7.5 Limite honnête à mentionner

Ces contrôles protègent contre les **accès non autorisés externes** et les
**erreurs de configuration**. Ils ne protègent pas contre :

- un **administrateur du cluster malveillant** — il peut toujours accéder à etcd
  et lire les secrets via l'API ;
- un **workload légitime qui, une fois compromis, utilise ses propres
  permissions** — tout est conforme, donc indétectable par le RBAC.

La **détection runtime (Falco)** est le complément naturel pour couvrir ce
dernier cas : elle alerte sur l'ouverture inattendue d'un fichier de secret par
un processus, sur un shell lancé dans un conteneur, ou sur une connexion
sortante inhabituelle. Ce n'est pas dans le périmètre de ce lab, et c'est
assumé — un secret ne peut pas être protégé d'un processus qui doit l'utiliser.

Formulation pour la soutenance :

> « Nous avons réduit la surface d'exposition et rendu la rotation possible
> sans interruption. Nous n'avons pas rendu le vol impossible : nous avons
> rendu le vol **coûteux, visible et de courte durée**. »
