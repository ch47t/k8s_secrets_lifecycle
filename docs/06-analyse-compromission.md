# Partie 6 — Analyse de sécurité et scénarios de compromission

> C'est la partie la plus importante pour la notation : elle montre que l'on
> comprend les **limites** de ce qui a été mis en place.

## 6.1 Blast radius : si le Pod `api-backend` est compromis

L'attaquant a obtenu une exécution de code dans le conteneur `api`. Que
peut-il faire, précisément ?

| Question | Réponse | Mécanisme qui l'impose |
|----------|---------|------------------------|
| Quels secrets sont accessibles via le ServiceAccount ? | `db-credentials` et `jwt-key` — **deux**, nommés | `Role` avec `resourceNames` (`backend-rbac.yaml`) |
| Peut-il lister les autres secrets ? | **Non** — `list` et `watch` refusés | Aucun verbe `list`/`watch` accordé |
| Peut-il accéder à d'autres namespaces ? | **Non** — un `Role` est namespacé | Pas de `ClusterRole` sur `secrets` |
| Peut-il modifier des ressources Kubernetes ? | **Non** — `get` uniquement, sur 2 objets | Aucun verbe `create`/`patch`/`delete` |
| Peut-il contacter Vault directement ? | **Non** — `vault:8200` bloqué depuis `backend` | `NetworkPolicy` `backend-egress-to-postgres` (allowlist) |
| Peut-il lire les secrets d'un autre Pod ? | Non via l'API ; via `pods/exec` non accordé | Pas de `pods/exec` |
| Peut-il lire les secrets qu'il monte ? | **Oui** — et c'est inévitable | Le kubelet fournit le volume, pas le RBAC |
| Peut-il joindre Internet ? | Non (egress allowlistée à DNS, PostgreSQL, API server) | `NetworkPolicy` |

**Réponse à la question attendue du plan** : avec les contrôles en place, le
blast radius est limité aux **deux secrets nommés** dans le `Role`, sans
possibilité de mouvement latéral vers d'autres namespaces ni accès à l'API
Kubernetes au-delà des permissions définies.

### La nuance que le plan ne dit pas, et qui compte

Le Pod backend n'a pas *besoin* du RBAC pour lire ses secrets : il les lit dans
un fichier fourni par le kubelet. Le `Role` sert la démonstration (et un usage
légitime de l'API), mais **le vrai contrôle du backend est ce qui est monté
dans le Pod** :

- `items:` limite le volume à 5 clés sur 5 et 1 clé sur 1 — si le Secret
  contenait demain un champ `admin_token`, il ne serait **pas** monté ;
- `defaultMode: 0400` + `runAsUser: 10001` : un autre processus du conteneur
  ne peut pas lire le fichier ;
- le volume est `readOnly: true`.

Une compromission du conteneur `api` donne donc accès à **S1, S2, S3** — soit
exactement ce dont l'application a besoin pour fonctionner. C'est le plancher
incompressible : on ne peut pas protéger un secret d'un processus qui doit
l'utiliser.

## 6.2 Scénarios de compromission

| Scénario | Impact **sans** contrôles | Impact **avec** contrôles | Limite résiduelle |
|----------|---------------------------|---------------------------|-------------------|
| **Compromission d'un Pod backend** | Accès à tous les secrets du namespace (`kubectl get secrets`) | Accès limité aux 2 secrets nommés dans le `Role` + ceux montés | Le Pod compromis peut **toujours** lire ses propres secrets : c'est structurel |
| **Compromission d'un ServiceAccount** (token exfiltré) | Accès à l'API avec tous les droits du SA (souvent `cluster-admin` en pratique) | RBAC minimal : seuls 2 secrets accessibles, `get` uniquement | Le token reste valide jusqu'à expiration (1 h par défaut). `automountServiceAccountToken: false` supprime ce vecteur sur frontend/database |
| **Fuite d'identifiants dans Git** | Credentials exposés publiquement, durée illimitée | Détection par gitleaks en pre-commit → le commit est bloqué | L'historique Git reste, même après suppression du fichier (démo 6) : il faut **révoquer**, pas seulement nettoyer |
| **Accès non autorisé à un Secret** (`kubectl get secret`) | Lecture directe réussie | `Forbidden` (403) : RBAC nominatif + absence de `list` | Un admin du cluster (`cluster-admin`) peut toujours tout lire |
| **Compromission du Pod ESO** | — | Accès aux secrets **synchronisés** uniquement (politique `eso-policy`) ; aucune capacité d'écriture dans Vault | ESO lit Vault pour N namespaces : sa compromission est plus grave que celle d'un Pod applicatif. À traiter par namespace dédié + `eso-policy` fine |
| **Compromission de Vault** | Tous les secrets exposés d'un coup | Unseal key partagée (Shamir), audit log, `deny` sur `sys/*` | Vault = SPOF critique : sa compromission est catastrophique. Pas de mitigation dans le lab |
| **Vol d'un snapshot etcd** | Tous les secrets en clair (`etcdctl get /registry/secrets/...`) | Données chiffrées `aescbc` : illisibles sans la clé | La clé de chiffrement vit hors cluster mais sur le poste de l'opérateur : sa fuite annule le contrôle |
| **Suppression d'un ExternalSecret** | — | `deletionPolicy: Retain` sur la base : PostgreSQL ne perd pas son mot de passe | Les autres secrets sont supprimés (comportement voulu) |
| **Attaque réseau interne** (Pod → Vault) | Lecture directe des secrets depuis Vault | `NetworkPolicy` : seul le namespace `external-secrets` atteint `vault:8200` | Dépend du CNI : kindnet n'applique pas toujours les politiques (voir 6.5) |
| **Utilisateur humain avec un kubeconfig trop large** | Lecture de tous les secrets | Groupe `developers` → `get jwt-key` seulement | Un certificat volé donne les droits du groupe pendant sa validité |

## 6.3 Ce que ces contrôles ne protègent PAS

Il faut le dire explicitement, c'est ce qui distingue une analyse d'un catalogue.

### a) L'administrateur malveillant

`cluster-admin` peut lire tous les secrets : il déchiffre via l'API. Aucun
contrôle RBAC ne s'y oppose. Les seules mitigations sont organisationnelles
(séparation des rôles, MFA, audit revu par une autre équipe, break-glass).

### b) Le workload légitime compromis

Si un attaquant est *dans* le Pod `api-backend`, il utilise ses permissions
légitimes : lire S1, S2, S3. C'est indétectable par le RBAC (tout est
conforme). **La détection runtime est le complément naturel** :

| Outil | Ce qu'il détecte |
|-------|------------------|
| **Falco** | `open()` d'un fichier de secret par un processus inattendu, shell lancé dans un conteneur, connexion sortante inhabituelle |
| **Audit log Kubernetes** | lecture de secret par une identité inattendue (déjà en place ici) |
| **Audit Vault** | lecture répétée d'un même chemin, accès depuis un token inhabituel |

Falco n'est pas déployé dans ce lab : c'est une extension naturelle, pas un
oubli silencieux.

### c) Les fuites hors du cluster

Une capture d'écran, un `kubectl describe` collé dans un ticket, un dump de
base contenant un hash de mot de passe : aucun contrôle Kubernetes ne couvre
cela. La formation et la revue de code restent nécessaires.

## 6.4 Matrice de risque résiduel

| Risque | Probabilité | Impact | Risque résiduel | Accepté ? |
|--------|-------------|--------|-----------------|-----------|
| Pod applicatif compromis → 3 secrets | Moyenne | Moyen | Faible (2 secrets nominatifs + NetworkPolicy) | Oui, incompressible |
| Token SA exfiltré → API | Moyenne | Faible | Faible (pas de `list`, 1 h de validité) | Oui |
| Snapshot etcd volé | Faible | Très élevé | Faible (aescbc) | Oui, sous réserve de protéger la clé |
| Vault compromis | Faible | Critique | **Élevé** | Non — nécessite HA + auto-unseal KMS en production |
| Admin malveillant | Très faible | Critique | **Élevé** | Oui (risque accepté, hors périmètre technique) |
| Secret commité par erreur | Moyenne | Élevé | Faible (gitleaks pre-commit) | Oui, avec revue |
| NetworkPolicy non appliquée par le CNI | Moyenne (kind) | Moyen | **Moyen** | Non — corriger par Calico (voir 6.5) |

## 6.5 Limites spécifiques à ce lab (à assumer à l'oral)

| Limite | Cause | Ce qu'il faudrait en production |
|--------|-------|-------------------------------|
| Vault en mode dev, stockage mémoire | Simplicité de démonstration | Vault HA (Raft 3 nœuds), PVC, TLS, auto-unseal KMS |
| Token root `root` connu | Mode dev | Aucun token root persistant ; provisionnement par Terraform + approle |
| NetworkPolicy possiblement inerte | kindnet n'applique pas toujours les politiques | Calico/Cilium (`make install-calico`), vérification par test de contrôle (`make netpol-check`) |
| `emptydir` pour PostgreSQL | kind n'a pas de provisionneur de stockage par défaut | PVC + StorageClass + snapshots |
| Backend interroge l'API Kubernetes | Nécessaire à la démo 2 | `automountServiceAccountToken: false` et suppression du `Role` |
| Certification des utilisateurs humains | Certificat client signé par la CA du cluster (démo 7) | OIDC (Dex, Keycloak) + groupes, pas de certificats à 1 an |
| Pas de détection runtime | Hors périmètre | Falco + alerting SIEM |

## 6.6 Comment reproduire cette analyse

```bash
make demo-1-acces-refuse      # prouve le refus (403)
make demo-2-acces-autorise    # prouve le périmètre exact accordé
make demo-3-chiffrement-etcd  # prouve que etcd ne livre rien
make demo-4-rotation          # prouve la rotation sans redémarrage
make demo-5-networkpolicy     # prouve l'isolation réseau
make demo-6-gitleaks          # prouve la détection dans Git
make demo-7-utilisateur       # prouve le moindre privilège humain
```

Chaque script se termine par un **tableau de conclusion** et un code de sortie
non nul si le résultat attendu n'est pas obtenu : les démonstrations sont
exécutables en CI, pas seulement jouables une fois à la main.
