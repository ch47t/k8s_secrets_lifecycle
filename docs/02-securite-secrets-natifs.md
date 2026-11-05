# Partie 2 — Sécurité des Secrets Kubernetes natifs

> Un Secret Kubernetes n'est pas un coffre-fort : c'est un objet de l'API,
> stocké dans etcd, dont la valeur est encodée en **Base64**. Base64 n'est pas
> du chiffrement. Sans `EncryptionConfiguration`, quiconque lit l'objet — ou
> accède à etcd — voit la valeur en clair.

## 2.1 Ce qui est appliqué dans ce dépôt

| Contrôle | Implémentation | Fichier |
|----------|----------------|---------|
| Secrets créés dans le bon namespace, hors Git | Créés par ESO depuis Vault, jamais commités | `infrastructure/eso/externalsecrets.yaml` |
| Chiffrement au repos dans etcd | `aescbc` (AES-256-CBC + HMAC), clé aléatoire 32 octets | `infrastructure/encryption/encryption-config.yaml.tpl` |
| Rechargement à chaud de la clé | `--encryption-provider-config-automatic-reload=true` | `clusters/kind-config.yaml.tpl` |
| Détection de fuite dans Git | gitleaks en pre-commit + scan d'historique | `.pre-commit-config.yaml`, `.gitleaks.toml` |
| Injection par volume, pas par `envFrom` | `volumes[].secret` + `volumeMounts` | `apps/backend/deployment.yaml` |
| Fichiers de secret en `0400` | `defaultMode: 0400` + `items` restrictifs | `apps/backend/deployment.yaml` |
| Audit des accès | politique d'audit niveau `Request` sur `secrets` | `infrastructure/encryption/audit-policy.yaml` |

## 2.2 Pourquoi `aescbc` et pas `secretbox` ?

| Provider | Chiffrement | Statut Kubernetes | Choix ici |
|----------|-------------|-------------------|-----------|
| `identity` | aucun | déconseillé (laisse tout en clair) | utilisé en **dernière** position uniquement pour migrer |
| `aescbc` | AES-256-CBC + HMAC-SHA256 | recommandé, disponible partout | **retenu** |
| `secretbox` | XSalsa20 + Poly1305 | plus rapide, plus récent | alternative valable |
| provider KMS (plugin) | clé dans un HSM/KMS | recommandé en production | hors périmètre du lab |

`aescbc` a été retenu parce qu'il est **explicable en une phrase** et que sa
clé est un simple bloc base64 de 32 octets — donc facile à gérer, à faire
tourner et à auditer. En production sur un cloud, on préfère un provider KMS :
la clé ne vit alors jamais dans un fichier.

## 2.3 Le piège du `identity: {}` en dernière position

```yaml
providers:
  - aescbc: { keys: [ { name: key1, secret: <32 octets base64> } ] }
  - identity: {}          # ⚠️ dernier provider = lecture seule, mais…
```

- **Écriture** : le premier provider chiffre → `aescbc`. Correct.
- **Lecture** : Kubernetes essaie les providers dans l'ordre ; `identity`
  permet de lire les objets **encore non chiffrés** (migration).
- **Le piège** : tant que `identity` est présent, *tous* les objets écrits
  avant l'activation du chiffrement restent lisibles en clair dans etcd.
  Il faut donc **réécrire** tous les secrets après activation :

```bash
kubectl get secrets -A -o json | kubectl replace -f -
```

C'est cette étape qui est oubliée dans la majorité des clusters « chiffrés ».
Le script `scripts/00-create-cluster.sh` crée le cluster *avec* le chiffrement
actif dès le départ : aucun objet en clair n'existe jamais, donc pas de
migration à faire — la posture la plus sûre.

## 2.4 Variable d'environnement vs volume monté

| Critère | `env` / `envFrom` | Volume monté |
|---------|-------------------|--------------|
| Visible dans `kubectl describe pod` | **Oui** (nom, parfois valeur selon l'outil) | Non |
| Visible dans `/proc/<pid>/environ` | **Oui** | Non |
| Hérité par les processus enfants | **Oui** | Non (il faut ouvrir le fichier) |
| Fuite dans un crash dump / log d'env | **Oui** | Non |
| Mis à jour après rotation | **Non** — figé au démarrage → redémarrage obligatoire | **Oui** — le kubelet réécrit le fichier (~60 s) |
| Contrôle de permission (mode UNIX) | Non | Oui (`0400`) |
| Choix de la clé exposée (`items`) | Non (tout ou rien) | Oui |
| Cas où il reste nécessaire | mot de passe d'une base qui ne sait pas lire un fichier (ex. `POSTGRES_PASSWORD`) | — |

**Décision du projet** :

- `api-backend` : **volume monté uniquement**, aucun `envFrom`. Le fichier est
  relu à chaque requête (aucun cache) → rotation transparente (démo 4).
- `postgres` : `secretKeyRef` sur `POSTGRES_PASSWORD`, avec une justification
  explicite dans le manifest — PostgreSQL ne peut pas relire un fichier pour
  son authentification. C'est une **limite assumée** : la rotation du mot de
  passe superutilisateur exige `ALTER USER`, donc une action explicite. Les
  *dynamic secrets* de Vault suppriment ce problème pour les rôles applicatifs
  (voir [05-vault-eso.md](05-vault-eso.md)).

## 2.5 Les manifests ne doivent jamais contenir de secret

Anti-pattern à ne jamais reproduire :

```yaml
apiVersion: v1
kind: Secret
metadata: { name: db-credentials, namespace: backend }
data:
  password: U3VwZXJTZWNyZXRQYXNzd29yZDEyMyE=   # ❌ base64, pas chiffré
```

Trois raisons, dans l'ordre de gravité :

1. **L'historique Git est éternel.** Supprimer le fichier ne supprime pas la
   valeur : `git log -p` la retrouve. Démonstration : démo 6.
2. **Le base64 est réversible par n'importe qui** (`base64 -d`). Ce n'est pas
   une protection, c'est un encodage.
3. **Un dépôt se clone.** Une seule copie suffit, et les forks survivent aux
   suppressions.

Conséquence appliquée : ce dépôt ne contient **aucun** `kind: Secret` avec des
données. Tous les `kind: Secret` produits le sont par ESO, à l'exécution.
Le validateur `make validate` vérifie cette propriété à chaque exécution.

## 2.6 Vérifier soi-même

```bash
# Ce que voit l'API (base64 — lisible par tous)
kubectl get secret db-credentials -n backend -o jsonpath='{.data.password}' | base64 -d

# Ce que contient réellement etcd (doit être illisible)
docker exec kind-control-plane etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert   /etc/kubernetes/pki/etcd/server.crt \
  --key    /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/backend/db-credentials
```

La sortie attendue commence par `k8s:enc:aescbc:v1:key1:`. Si elle contient du
JSON lisible, le chiffrement n'est pas actif — et tous les secrets du cluster
sont à considérer comme exposés.

Démonstration complète : [démo 3](07-demonstrations.md#démo-3).
