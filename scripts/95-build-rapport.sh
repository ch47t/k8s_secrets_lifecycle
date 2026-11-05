#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Assemble le dossier de rendu : docs/RAPPORT.md
#
# Pourquoi un script plutôt qu'un fichier écrit à la main ? Pour qu'il ne
# puisse PAS diverger des documents sources. Le rapport est une vue agrégée
# des neuf documents ; si l'un change, on régénère (make rapport).
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

OUT="$LAB_ROOT/docs/RAPPORT.md"
DOCS=(
  "01-matrice-secrets.md:Partie 1 — Matrice des secrets"
  "02-securite-secrets-natifs.md:Partie 2 — Sécurité des Secrets Kubernetes natifs"
  "03-rbac.md:Partie 3 — Gestion des accès et RBAC"
  "04-cycle-de-vie.md:Partie 4 — Cycle de vie des secrets"
  "05-vault-eso.md:Partie 5 — HashiCorp Vault et External Secrets Operator"
  "06-analyse-compromission.md:Partie 6 — Analyse de sécurité et scénarios de compromission"
  "07-demonstrations.md:Démonstrations et livrables"
  "08-comparaison-approches.md:Partie 7 — Comparaison des approches et réponse argumentée"
  "09-reponse-question-centrale.md:Réponse à la question centrale"
  "architecture.md:Architecture cible"
)

{
  cat <<'HEADER'
# Sécurisation du cycle de vie des secrets dans Kubernetes

**Mini-projet 6 — dossier de rendu**

Application de démonstration : frontend / API backend / PostgreSQL, déployés
dans trois namespaces isolés, avec Vault comme source de vérité des secrets et
External Secrets Operator comme pont de synchronisation.

> Ce document est **généré** à partir des fichiers de `docs/` par
> `make rapport`. Chaque partie est également disponible séparément, avec ses
> liens croisés vers le code.

---

## Sommaire

HEADER

  i=1
  for entry in "${DOCS[@]}"; do
    title="${entry#*:}"
    printf '%s. [%s](#%s)\n' "$i" "$title" "$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9éèàçùâêîôûëïü -]//g; s/ /-/g')"
    i=$((i + 1))
  done

  cat <<'INTRO'

---

## Résumé exécutif

| Question | Réponse courte | Preuve |
|----------|----------------|--------|
| Un Pod non autorisé peut-il lire un secret ? | Non — 403 Forbidden, token valide mais aucun droit | démo 1 |
| Un workload reçoit-il plus que nécessaire ? | Non — `get` sur des noms précis, jamais `list` | démo 2 |
| etcd protège-t-il les secrets ? | Oui — `aescbc`, préfixe `k8s:enc:aescbc:v1:key1` | démo 3 |
| Une rotation exige-t-elle un redémarrage ? | Non — Vault → ESO → volume, en moins de 90 s | démo 4 |
| Le backend peut-il joindre Vault directement ? | Non — NetworkPolicy | démo 5 |
| Un secret peut-il fuiter via Git ? | Détecté par gitleaks en pre-commit | démo 6 |
| Et un humain non autorisé ? | Refusé : le RBAC cible un groupe, pas un compte | démo 7 |

**Ce que le projet ne prétend pas faire** : protéger contre un administrateur
du cluster malveillant, ni contre un workload légitime compromis qui utilise
ses propres permissions. Voir la partie 6.

---

INTRO

  for entry in "${DOCS[@]}"; do
    file="${entry%%:*}"
    title="${entry#*:}"
    path="$LAB_ROOT/docs/$file"
    [ -f "$path" ] || { warn "document manquant : docs/$file"; continue; }
    printf '\n<div style="page-break-after: always"></div>\n\n'
    printf '# %s\n\n' "$title"
    # On retire le premier titre de niveau 1 du document source (doublon)
    awk 'NR==1 && /^# /{next} {print}' "$path"
    printf '\n---\n'
  done

  cat <<'FOOTER'

## Annexe — reproductibilité

```bash
make up                      # cluster + Vault + ESO + applications
make demos                   # les 7 démonstrations
make validate                # YAML + schémas Kubernetes + anti-patterns
make netpol-check            # preuve d'application des NetworkPolicy
make teardown                # destruction complète (clé etcd incluse)
```

## Annexe — inventaire des fichiers

Voir `README.md`, section « Structure du dépôt ». Tous les manifests sont
commentés en français ; les scripts sont vérifiés par `shellcheck`
(`.pre-commit-config.yaml`) et disposent d'un code de sortie non nul en cas
d'échec de démonstration.
FOOTER
} > "$OUT"

ok "Rapport généré : ${OUT#"$LAB_ROOT"/}"
detail "$(wc -l < "$OUT") lignes, $(wc -c < "$OUT" | awk '{printf "%.0f", $1/1024}') Ko"
