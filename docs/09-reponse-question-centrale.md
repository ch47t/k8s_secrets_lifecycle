# Réponse à la question centrale

> **Comment garantir que seuls les workloads et les utilisateurs autorisés
> peuvent accéder aux secrets nécessaires à leur fonctionnement ?**

La réponse tient en **quatre principes articulés**, plus une couche que les
quatre n'impliquent pas. Aucune technologie seule ne suffit : c'est leur
combinaison — et la vérification de chaque maillon — qui produit la garantie.

---

## Principe 1 — Identifier avant de protéger

On ne peut pas sécuriser ce qu'on n'a pas listé. La [matrice des secrets](01-matrice-secrets.md)
est le point de départ obligatoire : chaque secret a un propriétaire, un
consommateur, une durée de vie et un niveau de sensibilité.

**Pourquoi c'est un principe et pas une étape administrative** : la matrice a
révélé 11 secrets dont **trois hors du cluster** (clé d'unseal Vault, token
root, clé de chiffrement etcd). Sans cet inventaire, on aurait « sécurisé » les
secrets Kubernetes en laissant les trois plus critiques hors du périmètre.

**Preuve** : S1–S11 documentés avec consommateur, créateur, durée de vie et
analyse d'impact en cas de fuite.

---

## Principe 2 — Moindre privilège appliqué au RBAC

Un workload ne reçoit l'accès qu'aux secrets dont il a **strictement** besoin,
nommés explicitement dans `resourceNames` du `Role`. L'absence de
`resourceNames` est la première erreur de configuration à éviter — et
`list`/`watch` doivent être proscrits car ils contournent ce filtrage
(`list` ignore `resourceNames`).

**Preuve** :
- `sa-backend` → `get` sur 2 secrets nommés, rien d'autre ;
- `sa-frontend` → aucun accès, aucun token monté ;
- aucun `ClusterRole` applicatif sur les secrets ;
- `sa-intrus` → aucun droit, démontré par un 403 réel (démo 1) ;
- `make validate` vérifie mécaniquement l'absence de `list`/`watch`.

---

## Principe 3 — Ne jamais stocker un secret là où il n'est pas chiffré

Ni dans Git, ni dans une variable d'environnement de manifest, ni dans etcd
sans `EncryptionConfiguration`. **Le chiffrement au repos dans etcd est un
prérequis non négociable** : le RBAC protège l'API, pas le stockage.

**Preuve** :
- `aescbc` actif **dès la création** du cluster (aucun objet en clair n'a
  jamais existé) ;
- clé de chiffrement hors du cluster, `chmod 600`, gitignorée ;
- `identity: {}` uniquement pour la lecture de migration, jamais pour l'écriture ;
- aucun secret dans le dépôt, gitleaks en pre-commit (démo 6, démo 3).

---

## Principe 4 — Automatiser la rotation pour supprimer la fenêtre d'exposition

Un secret statique est un secret compromis en attente. Vault avec ses dynamic
secrets supprime le problème à la racine : les credentials ont une durée de vie
courte (5 min) et sont révocables instantanément (`DROP ROLE` à l'expiration du
lease).

**Preuve** : démo 4 — rotation complète en moins de 90 s, Pod non recréé,
`restartCount` inchangé ; `externalsecret-dynamic.yaml` pour les credentials
jetables.

---

## La couche supplémentaire : le réseau

Le RBAC répond à « qui peut lire quoi **dans l'API** ». Il ne dit rien du
trafic. Sans `NetworkPolicy`, un Pod compromis interroge Vault directement et
contourne ESO, RBAC et tout le reste.

**Preuve** : démo 5 — test de contrôle positif (backend → PostgreSQL : OK) puis
test négatif (backend → Vault : bloqué). Le contrôle positif est ce qui
distingue une démonstration d'une affirmation.

---

## Formulation synthétique pour la soutenance

> « Nous garantissons l'accès aux seuls composants autorisés par **quatre
> mécanismes qui se recoupent** : un inventaire qui définit le périmètre, un
> RBAC nominatif qui refuse tout le reste par défaut, un chiffrement au repos
> qui rend un vol de stockage inutile, et une rotation automatique qui rend un
> vol éventuel de courte durée. Une couche réseau empêche de contourner le
> premier mécanisme en parlant directement à la source de vérité. »

## Et la limite, dite explicitement

Ces contrôles protègent contre les accès non autorisés **externes** et les
**erreurs de configuration**. Ils ne protègent pas contre :

1. un **administrateur du cluster malveillant** — il peut lire les secrets via
   l'API ; seule une séparation organisationnelle des rôles limite ce risque ;
2. un **workload légitime compromis** — il utilise ses permissions légitimes :
   tout est conforme, donc indétectable par le RBAC. La **détection runtime
   (Falco)** est le complément nécessaire, hors périmètre de ce lab.

> Nous avons rendu le vol **coûteux, visible et de courte durée** ; nous ne
> l'avons pas rendu impossible. Un secret doit être lu par le processus qui
> l'utilise — c'est le plancher incompressible de tout système de secrets.
