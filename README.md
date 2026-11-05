# Mini-projet 6 — Sécurisation du cycle de vie des secrets dans Kubernetes

Architecture Kubernetes complète où les secrets — identifiants, clés API,
certificats — sont protégés à **chaque étape** de leur existence : création,
stockage, distribution, utilisation, rotation, révocation, suppression.

**Le problème** : les développeurs mettent des secrets dans des manifests Git,
utilisent des Secrets Kubernetes sans RBAC adapté et sans stratégie de rotation.
**La réponse** : Vault comme source de vérité, External Secrets Operator comme
pont, RBAC nominatif, chiffrement etcd, NetworkPolicy — et sept démonstrations
reproductibles qui prouvent que ça fonctionne.

```
Vault (source de vérité) ──30s──> ESO ──> Secrets K8s (chiffrés etcd)
                                              │
                                              ├─ volume monté 0400 ─> api-backend
                                              └─ secretKeyRef ─────> postgres
```

## Ce que le projet démontre

| Objectif du plan | Où c'est prouvé |
|------------------|-----------------|
| Un utilisateur non autorisé ne peut pas lire un secret | `make demo-1-acces-refuse`, `make demo-7-utilisateur` |
| Un workload ne reçoit que les secrets dont il a besoin | `make demo-2-acces-autorise` |
| La rotation n'implique pas de redémarrage manuel | `make demo-4-rotation` |
| Aucun secret en clair dans Git | `make demo-6-gitleaks` + `make validate` |
| Le stockage lui-même est protégé | `make demo-3-chiffrement-etcd` |
| Le blast radius est borné, y compris sur le réseau | `make demo-5-networkpolicy` |

## Démarrage rapide

**Prérequis** : `docker`, `kind`, `kubectl`, `helm`, `openssl` (et `gitleaks`
pour la démo 6, `kubeconform` pour la validation complète).

```bash
git clone <ce-dépôt> && cd k8s-secrets-lifecycle
make up          # cluster + Vault + ESO + applications  (~8 min la 1re fois)
make status      # état complet en une vue
open http://localhost:8080
```

Puis, dans l'ordre conseillé pour la soutenance :

```bash
make demo-1-acces-refuse        # 403 Forbidden depuis un Pod sans droit
make demo-2-acces-autorise      # accès nominatif + volume monté
make demo-3-chiffrement-etcd    # etcd ne contient que du chiffré
make demo-4-rotation            # rotation sans redémarrage (~2 min)
make demo-5-networkpolicy       # isolation réseau et blast radius
make demo-6-gitleaks            # un secret commité est détecté
make demo-7-utilisateur         # utilisateur humain non autorisé
```

`make teardown` détruit le cluster et les fichiers générés (clé etcd incluse).

> **Note** : les scripts nécessitent un cluster Kubernetes réel ; ils ne peuvent
> pas être exécutés dans un environnement sans Docker. `make validate` (YAML,
> schémas Kubernetes, anti-patterns) fonctionne partout.

## Structure du dépôt

```
.
├── apps/                        les trois composants de l'application
│   ├── backend/                 API python + Dockerfile + Deployment (volume monté)
│   ├── frontend/                nginx-unprivileged, aucun secret
│   └── database/                StatefulSet PostgreSQL + init SQL
├── clusters/
│   └── kind-config.yaml.tpl     chiffrement etcd + audit + port 8080
├── infrastructure/
│   ├── encryption/              EncryptionConfiguration (aescbc) + politique d'audit
│   ├── eso/                     ClusterSecretStore + ExternalSecrets
│   ├── namespaces/              6 namespaces + Pod Security Standards
│   ├── policies/                NetworkPolicy (default-deny + allowlist)
│   ├── rbac/                    ServiceAccounts, Roles, RoleBindings
│   └── vault/                   Vault dev, RBAC auth, politique, Job de bootstrap
├── demos/                       Pods de démonstration (intrus, tools, watcher)
├── scripts/                     00→02 déploiement, 10→16 démonstrations, 90→99 contrôles
├── docs/                        dossier de rendu complet
│   ├── 01-matrice-secrets.md
│   ├── 02-securite-secrets-natifs.md
│   ├── 03-rbac.md
│   ├── 04-cycle-de-vie.md
│   ├── 05-vault-eso.md
│   ├── 06-analyse-compromission.md
│   ├── 07-demonstrations.md
│   ├── 08-comparaison-approches.md
│   ├── 09-reponse-question-centrale.md
│   ├── architecture.md + architecture.svg
│   └── RAPPORT.md               document unique assemblé
├── Makefile                     toutes les cibles (make help)
├── .gitleaks.toml               détection de secrets
├── .pre-commit-config.yaml      gitleaks + yamllint + shellcheck
└── .gitignore                   protection structurelle des fichiers sensibles
```

## Documents à lire dans l'ordre

1. [Matrice des secrets](docs/01-matrice-secrets.md) — que protège-t-on, et pourquoi
2. [Secrets natifs](docs/02-securite-secrets-natifs.md) — Base64 n'est pas du chiffrement
3. [RBAC](docs/03-rbac.md) — le piège de `list` + `resourceNames`
4. [Cycle de vie](docs/04-cycle-de-vie.md) — les trois horloges de la rotation
5. [Vault + ESO](docs/05-vault-eso.md) — pourquoi ESO plutôt que l'Agent Injector
6. [Analyse de compromission](docs/06-analyse-compromission.md) — ce que ça ne protège pas
7. [Démonstrations](docs/07-demonstrations.md) — commandes, sorties attendues, plan B
8. [Comparaison des approches](docs/08-comparaison-approches.md)
9. [Réponse à la question centrale](docs/09-reponse-question-centrale.md)
10. [Rapport assemblé](docs/RAPPORT.md) — version « dossier de rendu »

## Choix techniques et leurs contreparties

| Choix | Pourquoi | Ce que ça coûte |
|-------|----------|-----------------|
| Vault en mode dev | Démonstration du cycle de vie en quelques minutes | Stockage mémoire, token root trivial — assumé et documenté |
| External Secrets Operator | Niveau intermédiaire, compatible GitOps, réversible | Le secret réside dans etcd (compensé par le chiffrement aescbc) |
| Chiffrement `aescbc` | Explicable, disponible partout, clé simple à gérer | Un provider KMS serait préférable en production |
| PostgreSQL en `${VAR}` d'env | PostgreSQL ne relit pas un fichier de secret | Rotation = `ALTER USER` + redémarrage, sauf rôles dynamiques |
| kind sans CNI additionnel | Installation rapide | NetworkPolicy possiblement non appliquée → `make install-calico` |
| `ClusterSecretStore` | Un seul point de configuration | Visible de tous les namespaces → restreint par `conditions` |

## Sécurité du dépôt lui-même

- **Aucun** `kind: Secret` avec des données : tous les secrets sont produits à
  l'exécution par ESO ou par `openssl`.
- La clé de chiffrement etcd et les `kubeconfig` sont gitignorés ; la clé est
  générée à la création du cluster et détruite au teardown.
- `gitleaks` en pre-commit bloque un commit contenant un secret.
- `make validate` refuse les anti-patterns : valeurs littérales, `list`/`watch`
  sur les secrets, conteneurs privilégiés, `envFrom` dans le backend.

## Licence et contexte

Projet pédagogique (mini-projet 6). Les manifests sont volontairement
surabondamment commentés : le code doit expliquer **pourquoi**, pas seulement
**quoi**.
