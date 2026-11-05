# Partie 3 — Gestion des accès et RBAC

> Le RBAC est la première ligne de défense des secrets. Objectif : chaque
> ServiceAccount ne peut lire que les secrets dont il a besoin, **et rien de plus**.

## 3.1 Architecture des identités

| ServiceAccount | Namespace | Droits sur les Secrets | Justification |
|----------------|-----------|------------------------|---------------|
| `sa-backend` | `backend` | `get` sur `db-credentials`, `jwt-key` — **nominatif** | Consomme S1, S3 |
| `sa-frontend` | `frontend` | **aucun** | Ne doit jamais connaître un credential |
| `sa-database` | `database` | `get` sur `db-credentials` | A besoin de S7 uniquement |
| `sa-eso` | `external-secrets` | écriture des Secrets cibles via le ClusterRole d'ESO ; lecture Vault via `eso-policy` | Pont Vault → K8s |
| `sa-intrus` | `security` | **aucun** (aucun Role, aucun RoleBinding) | Pod de démonstration |
| `vault-auth` | `vault` | aucun secret K8s ; `system:auth-delegator` pour TokenReview | Vérifier les JWT |

`automountServiceAccountToken` est passé à `false` partout où c'est possible
(frontend, database, outils). Conséquence importante : un Pod compromis **ne
peut même pas parler à l'API Kubernetes**. Pour `api-backend`, il reste à
`true` uniquement parce que la démo 2 interroge l'API ; la configuration
« production » est indiquée en commentaire dans le manifest.

## 3.2 Le Role du backend, ligne par ligne

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-backend
  namespace: backend
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-credentials", "jwt-key"]   # ← le cœur du sujet
    verbs: ["get"]                                  # ← ni list, ni watch
```

Trois décisions, chacune corrigeant une erreur fréquente :

| Élément | Ce qui arrive si on l'oublie |
|---------|------------------------------|
| `resourceNames` | `get` s'applique à **tous** les secrets du namespace |
| absence de `list` | `list` **ignore `resourceNames`** : `kubectl get secrets` listerait tous les noms → énumération gratuite |
| absence de `watch` | un attaquant observerait les rotations en temps réel (et les valeurs, sur les Secrets qu'il peut lire) |
| `namespace` explicite dans le `subjects` | un `RoleBinding` sans namespace prend celui du binding, mais un `ServiceAccount` mal nommé ailleurs échoue silencieusement |

### Le piège `list` + `resourceNames`

C'est la subtilité RBAC la plus importante du projet :

```yaml
# ❌ FAUX SENS DE SÉCURITÉ : resourceNames est ignoré pour list
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-credentials"]
    verbs: ["list"]
```

Avec cette règle, `kubectl get secrets -n backend` renvoie **tous** les secrets
du namespace (les noms ; les valeurs restent protégées par `get`). Mais
l'énumération donne la carte du trésor : noms, tailles, dates de rotation,
annotations `owner`. Pire : `list` + `get` sur les noms découverts ne
fonctionne pas, mais `list` seul suffit à cibler une attaque.

**Règle du projet : aucun `list`, aucun `watch`, aucun `*` sur `secrets`.**
Vérifié mécaniquement par `make validate`.

## 3.3 Permissions dangereuses — inventaire et interdiction

| Permission | Risque | Statut dans le projet |
|------------|--------|----------------------|
| `verbs: ["list"]` sur `secrets` | Expose tous les noms de secrets, facilite l'énumération | **Interdit** (vérifié par `make validate`) |
| `verbs: ["watch"]` sur `secrets` | Interception des changements en temps réel | **Interdit** |
| `resourceNames` absent | Accès à TOUS les secrets du namespace | **Interdit** par convention + revue |
| `ClusterRole` sur `secrets` | Accès cross-namespace, blast radius maximal | **Aucun ClusterRole** applicatif ne porte sur les secrets |
| `create`/`update` sur `secrets` | Injection d'un secret forgé (ex. empoisonner `jwt-key`) | Aucun workload ne l'a ; seul ESO écrit |
| `escalate` / `bind` sur `roles`/`clusterroles` | Contournement total du RBAC | Non accordé |
| `impersonate` | Usurpation d'identité (dont les contrôleurs) | Non accordé |
| `pods/exec` | Rebond vers le SA d'un autre Pod | Non accordé aux workloads |
| `serviceaccounts/token` | Fabrication de jetons pour un autre SA | Non accordé |
| accès à `nodes/proxy` | Contournement de l'API et de l'audit | Non accordé |

Le ClusterRole existant dans le dépôt (`vault-auth-delegator`) est volontairement
limité à `system:auth-delegator` : il permet uniquement de créer des
`TokenReview` et `SubjectAccessReview`, pas de lire un secret.

## 3.4 Pourquoi pas de `ClusterRole` pour les secrets ?

Un `ClusterRole` lié via `ClusterRoleBinding` donne le même droit **dans tous
les namespaces, y compris ceux créés plus tard**. C'est le « blast radius
maximal » : une compromission dans `frontend` donne les secrets de `backend`,
`database`, et de tout namespace futur. Le projet n'utilise que des `Role`
(namespacés) + un `ClusterSecretStore` **restreint par `conditions`** pour ESO
(cf. `infrastructure/eso/cluster-secret-store.yaml`).

## 3.5 Le RBAC ne contrôle pas tout (à dire à l'oral)

Trois limites structurelles, qui justifient les autres couches :

1. **Le kubelet n'utilise pas le RBAC** pour fournir un secret monté. Un Pod
   dont le SA n'a *aucun* droit peut quand même consommer un secret monté →
   c'est pour cela que le contrôle réel est *ce qu'on monte dans le Pod*.
2. **Un administrateur du cluster lit tout.** `cluster-admin` peut lire les
   secrets (chiffrés dans etcd mais déchiffrés par l'API). Aucun RBAC ne
   protège contre l'admin malveillant.
3. **Le RBAC ne contrôle pas le réseau.** Un Pod peut appeler Vault
   directement si NetworkPolicy ne l'en empêche pas → démo 5.

## 3.6 Vérifier soi-même

```bash
# Le backend peut-il lire ce qu'il doit lire ?
kubectl auth can-i get secret/db-credentials -n backend \
  --as=system:serviceaccount:backend:sa-backend        # yes

# Peut-il énumérer ? (doit être non)
kubectl auth can-i list secrets -n backend \
  --as=system:serviceaccount:backend:sa-backend        # no

# Le frontend a-t-il un accès ? (doit être non)
kubectl auth can-i get secrets -n frontend \
  --as=system:serviceaccount:frontend:sa-frontend      # no

# Le SA intrus a-t-il un accès ? (doit être non)
kubectl auth can-i --list -n security \
  --as=system:serviceaccount:security:sa-intrus
```

Démonstrations : [démo 1](07-demonstrations.md#démo-1) (refus),
[démo 2](07-demonstrations.md#démo-2) (accès nominatif),
[démo 7](07-demonstrations.md#démo-7) (utilisateur humain).
