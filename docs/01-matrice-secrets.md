# Partie 1 — Matrice des secrets

> « Un secret qu'on n'a pas identifié ne sera pas protégé. »
> Cette matrice est le point de départ de tout le reste : chaque ligne justifie
> une décision de RBAC, de chiffrement ou de rotation dans les parties suivantes.

## 1.1 Inventaire exhaustif

| # | Secret | Composant consommateur | Type | Sensibilité | Créé par | Durée de vie attendue |
|---|--------|------------------------|------|-------------|----------|-----------------------|
| S1 | Mot de passe PostgreSQL | `api-backend` | Identifiant DB | **Critique** | Vault (seed initial aléatoire), distribué par ESO | 30 jours (cible) / rotation à la demande |
| S2 | URL de connexion DB | `api-backend` | Identifiant DB | **Critique** | Composée à partir de S1 (host/port/db non secrets) | Identique à S1 |
| S3 | Clé JWT de signature | `api-backend` | Clé cryptographique | **Critique** | Vault KV (`secret/backend/jwt-key`) | 90 jours, avec chevauchement de 24 h pour ne pas invalider les tokens en vol |
| S4 | Clé API service externe | `api-backend` | Token API | Haute | Fournisseur partenaire → Vault | 180 jours, imposée par le fournisseur |
| S5 | Certificat TLS | Ingress / frontend | Certificat x509 | Haute | ACME / cert-manager → Secret TLS | 90 jours (Let's Encrypt) |
| S6 | Token d'authentification CI/CD | Pipeline GitLab/GitHub | Token de service | Haute | Plateforme CI → OIDC éphémère | Une exécution de pipeline (< 1 h) |
| S7 | Mot de passe PostgreSQL vu par la base | `postgres` | Identifiant DB | **Critique** | Vault, synchronisé par ESO | Identique à S1 |
| S8 | Jeton de ServiceAccount ESO | `external-secrets` | Token de service | Haute | Kubernetes (projeté) | 20 min (TTL du token Vault) |
| S9 | Clé de scellement Vault (unseal) | Opérateur humain | Clé cryptographique | **Critique** | Shamir 3/5, hors cluster | Permanente (rotation annuelle) |
| S10 | Token root Vault | Opérateur | Token privilégié | **Critique** | Initialisation Vault | Usage unique, révoqué immédiatement après le bootstrap |
| S11 | Clé de chiffrement etcd (aescbc) | kube-apiserver | Clé cryptographique | **Critique** | Générée par l'opérateur, hors cluster | Rotation semestrielle |

> Dans ce lab, S9 et S10 sont simplifiés (Vault en mode dev, token `root`
> trivial). C'est assumé et documenté comme limite : voir
> [06-analyse-compromission.md](06-analyse-compromission.md).

## 1.2 Qui crée, qui consomme, qui peut lire

| Secret | Namespace | Créé par | Consommé par | Lisible par (RBAC) | Stocké dans etcd ? |
|--------|-----------|----------|--------------|--------------------|--------------------|
| S1/S2 | `backend` | ESO | `api-backend` (volume) | `sa-backend` uniquement, `get` seulement | Oui, **chiffré** |
| S3 | `backend` | ESO | `api-backend` (volume) | `sa-backend` (get) + groupe `developers` (get) | Oui, **chiffré** |
| S4 | `backend` | ESO | `api-backend` (volume) | **Personne** côté workload : ESO écrit, le Pod le monte | Oui, **chiffré** |
| S5 | `frontend` | cert-manager | Ingress | Contrôleur d'Ingress | Oui, chiffré |
| S6 | — | OIDC du runner CI | Pipeline (durée du job) | Aucun stockage permanent | **Non** (jeton éphémère) |
| S7 | `database` | ESO | `postgres` (env) | `sa-database` (get) | Oui, **chiffré** |
| S8 | `external-secrets` | Kubernetes | ESO (vers Vault) | Vault via TokenReview | Non (token projeté, en mémoire) |
| S9/S10 | hors cluster | Opérateur | Opérateur | — | Non |
| S11 | hors cluster | Opérateur | kube-apiserver | — | Non (fichier dans le nœud) |

**Le cas S4 est volontairement paradoxal** et c'est le point le plus intéressant
de la matrice : la clé API du partenaire est présente dans le namespace
`backend`, mais `sa-backend` ne peut pas la lire via l'API (elle n'est pas dans
`resourceNames`). Le Pod la consomme pourtant… parce qu'il l'a montée en
volume. Autrement dit : *lire un secret et le consommer sont deux permissions
distinctes*, et le RBAC ne contrôle que la première. Ce point est démontré en
[démo 2](07-demonstrations.md#démo-2).

## 1.3 Analyse d'impact en cas de fuite

| Secret | Vecteur de fuite réaliste | Impact immédiat | Impact différé | Détection | Réduction du dommage |
|--------|---------------------------|-----------------|----------------|-----------|----------------------|
| S1 (mdp DB) | Log applicatif, dump etcd, `kubectl describe` | Lecture/écriture de toute la base applicative | Exfiltration de données personnelles, RGPD | Audit log API, logs PostgreSQL (`log_connections`) | Rotation + `ALTER USER` ; TTL DB court |
| S2 (URL DB) | ConfigMap commitée, message d'erreur | Idem S1 si le mot de passe y figure | Idem | gitleaks pre-commit | Ne jamais mettre l'URL complète ; seulement les composants |
| S3 (JWT) | Volume monté exfiltré, image compromise | **Forge de tokens valides pour n'importe quel utilisateur** | Prise de contrôle de comptes, contournement total de l'authentification | Anomalies de `kid`/`iat` | Rotation avec chevauchement, `kid` en en-tête |
| S4 (clé API) | Log d'appel sortant, dépôt public | Consommation du quota du partenaire | Facturation, blocage du compte partenaire | Alertes de débit côté fournisseur | Révocation côté fournisseur (seule action efficace) |
| S5 (TLS) | Partage du fichier `.pem` | Usurpation du domaine, MITM | Perte de confiance, vols de session | Certificate Transparency | Réémission + révocation OCSP |
| S6 (CI/CD) | Log de pipeline, `.gitlab-ci.yml` | Déploiement d'une image malveillante | Persistance dans le cluster | Audit des `deployments` | OIDC à durée de vie = durée du job, scopes minimaux |
| S9/S10 (Vault) | Post-it, partage de mot de passe, dump mémoire | **Tous les secrets, d'un coup** | Compromission totale et durable | Audit device Vault, alerte sur `sys/*` | Scellement Shamir 3/5, auto-unseal KMS, tokens à TTL court |

## 1.4 Règles dérivées de la matrice

Ces règles sont appliquées mécaniquement dans le code du dépôt :

1. **Aucun secret dans Git** — la matrice ne contient aucun *nom de variable*
   secret, seulement des identifiants (S1…S11). Voir `.gitleaks.toml`.
2. **Un consommateur = un ServiceAccount** — ni `default`, ni partage entre
   composants (`infrastructure/rbac/serviceaccounts.yaml`).
3. **`resourceNames` obligatoire** pour tout accès aux Secrets
   (`infrastructure/rbac/backend-rbac.yaml`).
4. **Le secret le plus sensible commande le contrôle le plus fort** :
   S1/S3 → volume monté + rotation automatique ; S5 → géré par cert-manager ;
   S9/S10 → jamais dans le cluster.
5. **Tout secret a une date de mort** : un secret sans TTL est un secret
   compromis en attente (partie 4).
