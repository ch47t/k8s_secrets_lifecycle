# Démonstrations attendues et livrables

> Chaque démonstration est un script reproductible, avec un **résultat attendu
> explicite** et un code de sortie non nul en cas d'échec. L'objectif n'est pas
> de montrer que les contrôles *existent*, mais qu'ils *fonctionnent*.

## Vue d'ensemble

| # | Commande | Ce que ça prouve | Durée |
|---|----------|------------------|-------|
| 1 | `make demo-1-acces-refuse` | Un Pod sans droit ne peut pas lire un secret (403) | ~20 s |
| 2 | `make demo-2-acces-autorise` | Le backend lit **uniquement** ses 2 secrets, par volume monté | ~20 s |
| 3 | `make demo-3-chiffrement-etcd` | etcd ne contient que du chiffré (`k8s:enc:aescbc:v1:key1`) | ~15 s |
| 4 | `make demo-4-rotation` | Rotation Vault → ESO → Pod **sans redémarrage** | ~2 min |
| 5 | `make demo-5-networkpolicy` | Le backend ne peut pas joindre Vault (blast radius) | ~30 s |
| 6 | `make demo-6-gitleaks` | Un secret dans Git est détecté (pre-commit + historique) | ~30 s |
| 7 | `make demo-7-utilisateur` | Un utilisateur humain non autorisé est refusé | ~30 s |

---

<a id="démo-1"></a>
## Démo 1 — Accès refusé (non autorisé)

**Question posée** : un attaquant qui obtient une exécution de code dans le
cluster peut-il lire `db-credentials` ?

**Mise en scène** : un Pod `intrus` dans le namespace `security`, avec le
ServiceAccount `sa-intrus`. Ce SA possède un token valide
(`automountServiceAccountToken: true`) mais **aucun Role, aucun RoleBinding**.
C'est le pire cas réaliste : un token d'API entre les mains de l'attaquant.

```bash
make demo-1-acces-refuse
```

**Résultat attendu** :

```
kubectl auth can-i get secrets -n backend      -> no
kubectl auth can-i list secrets -n backend     -> no
kubectl auth can-i get secrets -A              -> no

$ kubectl get secret db-credentials -n backend -o jsonpath='{.data.password}'
Error from server (Forbidden): secrets "db-credentials" is forbidden:
  User "system:serviceaccount:security:sa-intrus" cannot get resource
  "secrets" in API group "" in the namespace "backend"
```

**Le point à souligner à l'oral** : *l'authentification réussit, l'autorisation
échoue*. L'API reconnaît parfaitement l'identité du demandeur ; c'est le RBAC
qui refuse. Un token valide ne vaut rien sans permission.

**Bonus** : le script extrait la tentative depuis l'**audit log** du cluster —
on voit l'identité, le verbe, la ressource et le code 403.

---

<a id="démo-2"></a>
## Démo 2 — Accès autorisé (nominatif, par volume)

**Question posée** : le backend reçoit-il *tout juste* ce dont il a besoin ?

**Ce que le script démontre, dans l'ordre** :

| Étape | Attendu |
|-------|---------|
| `get secret db-credentials` depuis le Pod | autorisé |
| `get secret jwt-key` depuis le Pod | autorisé |
| `get secret external-api-key` (même namespace !) | **Forbidden** |
| `get secrets` (liste) | **Forbidden** |
| Variables d'environnement du conteneur | aucune valeur de secret |
| Fichiers montés | `/etc/app-secrets/db-credentials/*` en `0400` |
| `/api/db-check` | connexion PostgreSQL réussie avec le secret monté |

```bash
make demo-2-acces-autorise
```

**Le point le plus intéressant** : `external-api-key` **existe** dans le
namespace `backend`, et le Pod pourrait le monter — mais `sa-backend` ne peut
pas le **lire** via l'API, car son nom n'est pas dans `resourceNames`.

Cela illustre une distinction que le plan ne formule pas explicitement :

> **Consommer un secret** (le kubelet le monte dans un volume) et **lire un
> secret** (appeler l'API) sont deux permissions différentes. Le RBAC ne
> contrôle que la seconde.

Conséquence pratique : la vraie surface d'exposition du backend est définie par
le bloc `items:` de son volume, pas seulement par le `Role`.

---

<a id="démo-3"></a>
## Démo 3 — Chiffrement au repos dans etcd

**Question posée** : si quelqu'un vole un snapshot etcd, obtient-il les
secrets ?

```bash
make demo-3-chiffrement-etcd
```

**Ce que le script affiche** :

1. Les arguments de l'API server (`--encryption-provider-config`, `--audit-policy-file`)
2. La valeur **base64** renvoyée par l'API — lisible en une commande
   (`base64 -d`), donc **pas une protection**
3. La valeur **réellement stockée** dans etcd :

```
k8s:enc:aescbc:v1:key1:<données binaires illisibles>
```

4. Une **preuve négative** : ni le mot de passe, ni son base64 n'apparaissent
   dans la sortie d'etcd.
5. La procédure de rotation de la clé de chiffrement.

**Le point à souligner** : le RBAC protège l'API, **pas le stockage**. Un
`etcdctl get /registry/secrets/...` ne demande aucune permission Kubernetes.
Sans `EncryptionConfiguration`, un accès disque ou une sauvegarde non chiffrée
livre tous les secrets du cluster.

**Piège à mentionner** : garder `identity: {}` en dernier provider laisse les
objets antérieurs en clair. Il faut réécrire les secrets après activation.

---

<a id="démo-4"></a>
## Démo 4 — Rotation sans redémarrage

**Question posée** : peut-on changer un mot de passe sans intervention ni
redéploiement ?

C'est **la** démonstration centrale du projet. Le script automatise la
séquence complète :

1. Il relève les **témoins** : UID du Pod, date de création, `restartCount`,
   empreinte SHA-256 du mot de passe vue par l'application.
2. Il lance un Pod `rotation-watcher` qui monte le secret et imprime
   l'empreinte du fichier toutes les 10 s (preuve visuelle du changement).
3. Il change **réellement** le mot de passe dans PostgreSQL
   (`ALTER USER app WITH PASSWORD ...`), puis écrit la même valeur dans
   **Vault** (KV v2, nouvelle version).
4. ESO détecte le changement (`refreshInterval: 30s`) et met à jour le Secret
   dans les deux namespaces.
5. Le kubelet propage le nouveau contenu dans le volume monté.
6. Le script vérifie : nouvelle empreinte côté application, connexion
   PostgreSQL fonctionnelle, **Pod non recréé**.

```bash
make demo-4-rotation
```

**Tableau final attendu** :

| Témoin | Avant | Après |
|--------|-------|-------|
| Empreinte du mot de passe (app) | `a1b2c3d4e5f6` | `9f8e7d6c5b4a` |
| UID du Pod | `6f2a…` | `6f2a…` (identique) |
| Création du Pod | `14:32:10` | `14:32:10` (identique) |
| `restartCount` | `0` | `0` |

**Les trois raisons du succès** (à énoncer) :

1. Le secret est **monté en volume** : le kubelet met le fichier à jour.
   Avec `envFrom`, il faudrait redémarrer.
2. L'application **relit le fichier à chaque requête** (aucun cache).
3. ESO **réconcilie périodiquement** (`refreshInterval`) : aucun webhook, aucune
   action manuelle.

**Durée mesurée** : 30 à 90 secondes (TTL ESO + période de synchronisation du
kubelet). Ce n'est pas instantané, et il faut le dire.

**Variante « fenêtre nulle »** : `kubectl apply -f infrastructure/eso/externalsecret-dynamic.yaml`
— Vault crée alors un utilisateur PostgreSQL jetable (TTL 5 min) : le
credential est généré **à la demande**, il n'y a plus rien à faire tourner.

---

<a id="démo-5"></a>
## Démo 5 — Isolation réseau et blast radius

**Question posée** (celle du plan, partie 6) : le Pod backend peut-il
contacter Vault directement ?

```bash
make demo-5-networkpolicy
```

**Méthode rigoureuse — un test négatif seul ne prouve rien.** Le script fait
d'abord un **test de contrôle** positif :

```
[contrôle] backend -> postgres:5432   : CONNECTÉ      (le réseau fonctionne)
[test]     backend -> vault:8200      : timeout       (politique appliquée)
[test]     security -> postgres:5432  : refusé        (namespace non autorisé)
```

Sans le contrôle positif, un échec réseau se confond avec une politique — c'est
l'erreur méthodologique classique.

**Matrice des flux** :

| Source | Destination | Autorisé |
|--------|-------------|----------|
| `frontend` | `backend:8080` | oui |
| `backend` | `postgres:5432` | oui |
| `backend` | `vault:8200` | **NON** |
| `backend` | autre namespace / Internet | **NON** |
| `external-secrets` (ESO) | `vault:8200` | oui |
| `vault` | `postgres:5432` | oui (dynamic secrets) |
| `security` (intrus) | tout | **NON** |

**Limite à assumer** : un objet `NetworkPolicy` n'est qu'une **intention**. Si
le CNI ne l'implémente pas (kindnet sur certaines versions), les politiques
sont appliquées par l'API mais **jamais exécutées**. D'où :

```bash
make netpol-check       # verdict : appliquées / non concluant / non appliquées
make install-calico     # recrée le cluster avec un CNI qui applique les politiques
```

La distinction entre « politique présente » et « politique appliquée » est
précisément le genre de nuance attendue dans l'analyse.

---

<a id="démo-6"></a>
## Démo 6 — Secrets dans Git

**Question posée** : peut-on garantir qu'aucun secret n'est exposé dans le
dépôt ?

```bash
make demo-6-gitleaks
```

**Trois volets** :

1. **État du dépôt** : `.gitignore` protège la clé de chiffrement etcd, les
   `.env`, `*.key`, `*.pem`, `kubeconfig*`. Le dépôt ne contient **aucun**
   `kind: Secret` avec des données.
2. **Injection volontaire** : le script crée un dépôt jetable contenant un
   manifest fautif (mot de passe en base64 + clés AWS factices) et lance
   gitleaks → **détection** → le commit aurait été bloqué en pre-commit.
3. **Le piège de l'historique** : le fichier est supprimé, un commit de
   suppression est créé… et gitleaks le retrouve toujours avec
   `--log-opts=--all`. **Supprimer un fichier ne supprime pas le secret.**

**Conclusion à énoncer** :

> Après une fuite, la seule action qui protège est la **révocation**. Le
> nettoyage de l'historique (`git filter-repo`) vient après, et ne restaure
> jamais la confidentialité : il faut considérer la valeur comme publique.

---

<a id="démo-7"></a>
## Démo 7 — Utilisateur humain non autorisé

**Question posée** : le moindre privilège s'applique-t-il aussi aux humains ?

Le script génère un certificat client signé par la CA du cluster
(`CN=alice`, `O=developers`), construit un kubeconfig dédié, puis teste :

| Commande d'alice | Résultat attendu |
|------------------|------------------|
| `get secret jwt-key` | autorisé (usage de debug légitime) |
| `get secret db-credentials` | **Forbidden** |
| `get secret external-api-key` | **Forbidden** |
| `kubectl get secrets` (liste) | **Forbidden** |
| `get secrets -n frontend` | **Forbidden** |

```bash
make demo-7-utilisateur
```

**Points à souligner** :

- Le `RoleBinding` cible le **groupe** `developers`, pas l'utilisatrice : le
  départ d'alice ne casse rien, l'arrivée d'un collègue ne demande aucun
  changement.
- Le certificat est à **1 jour** de validité dans la démo (en production :
  OIDC avec des sessions courtes, pas des certificats à 1 an).
- La tentative est tracée dans l'audit log.
- La clé privée de la CA est supprimée à la fin du script — même en lab, on ne
  la laisse pas traîner.

---

## Livrables documentaires

| Livrable | Fichier |
|----------|---------|
| Matrice des secrets (partie 1) | [01-matrice-secrets.md](01-matrice-secrets.md) |
| Manifests YAML commentés | `infrastructure/`, `apps/`, `demos/` |
| Schéma d'architecture | [architecture.md](architecture.md), [architecture.svg](architecture.svg) |
| Analyse des scénarios de compromission (partie 6) | [06-analyse-compromission.md](06-analyse-compromission.md) |
| Comparaison des approches | [08-comparaison-approches.md](08-comparaison-approches.md) |
| Réponse à la question centrale | [09-reponse-question-centrale.md](09-reponse-question-centrale.md) |
| Procédure de démonstration (ordre, durée, plan B) | ci-dessous |

## Ordre de passage conseillé (15–20 min)

| Temps | Action | Message |
|-------|--------|---------|
| 2 min | Schéma d'architecture au tableau | Trois namespaces, Vault, ESO, RBAC |
| 2 min | `make demo-1-acces-refuse` | « Authentification ≠ autorisation » |
| 2 min | `make demo-2-acces-autorise` | « Nominatif, et volume ≠ lecture API » |
| 2 min | `make demo-3-chiffrement-etcd` | « Base64 n'est pas du chiffrement » |
| 3 min | `make demo-4-rotation` | « Zéro redémarrage », montrer le tableau avant/après |
| 2 min | `make demo-5-networkpolicy` | « Le blast radius est aussi une question réseau » |
| 2 min | `make demo-6-gitleaks` | « Un secret commité est un secret perdu » |
| 3 min | Partie 6 : ce que ça ne protège pas | Falco, admin malveillant, Vault = SPOF |

## Plan B (si quelque chose casse pendant la soutenance)

| Panne | Solution immédiate |
|-------|--------------------|
| Cluster absent | `make cluster` (2 min) puis `make up` (5 min) |
| ESO ne synchronise pas | `kubectl describe externalsecret -n backend db-credentials` — cause en fin de sortie |
| Rotation trop lente | Montrer `kubectl get externalsecret -o jsonpath='{.status.refreshTime}'` : la synchro a eu lieu, c'est le kubelet qui prend jusqu'à 60 s |
| NetworkPolicy non appliquée | L'annoncer comme limite CNI et montrer `make netpol-check` : c'est une preuve de maturité, pas un échec |
| Plus de réseau | Les scripts sont dans le dépôt ; les captures de sortie attendue sont dans ce document |
