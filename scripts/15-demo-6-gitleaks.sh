#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 6 — « Les secrets ne sont jamais exposés en clair dans un dépôt Git »
#
# Deux volets :
#   1. état du dépôt : aucun secret réel, .gitignore qui protège les fichiers
#      générés (clé aescbc, kubeconfig, fichiers .env) ;
#   2. détection : on injecte volontairement des faux secrets dans une copie
#      jetable et on montre que gitleaks les trouve AVANT le commit
#      (pre-commit) — et qu'il trouve aussi un secret déjà présent dans
#      l'HISTORIQUE, même après suppression du fichier.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

title "DÉMO 6 — Détection de secrets dans Git"

step "1. Contenu du .gitignore (protection des fichiers générés)"
sed 's/^/    /' "$LAB_ROOT/.gitignore"

printf '\n'
step "2. Recherche de secrets dans le dépôt actuel"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$LAB_ROOT" --no-banner --redact 2>&1 | tail -12 | sed 's/^/    /'
  ok "Aucun secret attendu dans le dépôt versionné"
else
  warn "gitleaks non installé — installation suggérée :"
  detail "brew install gitleaks   |   docker pull zricethezav/gitleaks:latest"
fi

printf '\n'
step "3. Injection de faux secrets dans un dépôt jetable (démo)"
TMP="$(mktemp -d)"
cp -r "$LAB_ROOT" "$TMP/repo" 2>/dev/null || true
cd "$TMP/repo"
git init -q . 2>/dev/null || true
git config user.email "demo@lab.local"; git config user.name "demo"

cat > "$TMP/repo/backend-manifest-fautif.yaml" <<'BAD'
# Fichier VOLONTAIREMENT dangereux : c'est l'anti-exemple du projet.
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: backend
type: Opaque
data:
  # ❌ Le péché originel : un secret commité « juste une fois »
  password: U3VwZXJTZWNyZXRQYXNzd29yZDEyMyE=
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-config
data:
  # ❌ Clé API en clair dans un ConfigMap
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
BAD
git add -A 2>/dev/null; git commit -qm "feat: ajout des credentials (à ne jamais faire)" 2>/dev/null || true
detail "Faux secrets introduits dans : backend-manifest-fautif.yaml"

printf '\n'
step "4. gitleaks analyse l'historique du dépôt"
if command -v gitleaks >/dev/null 2>&1; then
  set +e
  gitleaks detect --source . --no-banner --redact --verbose >/tmp/gitleaks.out 2>&1
  RC=$?
  set -e
  head -30 /tmp/gitleaks.out | sed 's/^/    /'
  if [ "$RC" -ne 0 ]; then
    ok "gitleaks a détecté les secrets -> le commit aurait été BLOQUÉ en pre-commit"
  else
    warn "Aucune détection : vérifiez la version de gitleaks"
  fi
else
  docker run --rm -v "$TMP/repo:/repo" zricethezav/gitleaks:latest \
    detect --source /repo --no-banner --redact --verbose 2>&1 | head -30 | sed 's/^/    /' || true
fi

printf '\n'
step "5. Le fichier est supprimé, le secret reste dans l'historique"
rm -f "$TMP/repo/backend-manifest-fautif.yaml"
git add -A && git commit -qm "chore: suppression du fichier de credentials" || true
detail "Le fichier n'existe plus dans le HEAD… mais il est toujours dans l'historique :"
git log --oneline --all | sed 's/^/      /'
echo "      git show HEAD~1:backend-manifest-fautif.yaml -> toujours lisible"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --no-banner --redact --log-opts="--all" 2>&1 | tail -5 | sed 's/^/    /' || true
fi
warn "CONCLUSION : supprimer un fichier ne supprime PAS le secret. Il faut :"
detail "1. RÉVOQUER le secret (Vault, PostgreSQL, fournisseur d'API) — la seule action qui protège"
detail "2. puis nettoyer l'historique (git filter-repo) si le dépôt est public"
detail "3. et considérer que la valeur a fuité : la rotation est obligatoire"

printf '\n'
step "6. Pre-commit hook fourni avec le projet"
sed 's/^/    /' "$LAB_ROOT/.pre-commit-config.yaml" 2>/dev/null | head -20

cd "$LAB_ROOT"
rm -rf "$TMP"

printf '\n%s%sCONCLUSION DÉMO 6%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Un secret commité est un secret perdu : l'historique est éternel, et un
  dépôt se clone. La seule stratégie qui tient est en amont :
    - aucun secret dans le dépôt (Vault est la source de vérité)
    - gitleaks en pre-commit (bloque) + en CI (détecte après coup)
    - .gitignore sur tout ce qui est généré (clés, kubeconfig, .env)
C
C
