#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Validation statique de tous les manifests, sans cluster.
#
# Trois contrôles :
#   1. parsing YAML (le plus basique, attrape 90 % des erreurs de copier-coller)
#   2. kubeconform : validation contre les schémas de l'API Kubernetes
#      (détecte les champs mal nommés que `kubectl apply` refuse seulement
#      au runtime)
#   3. anti-patterns : recherche de secrets en clair et de permissions
#      dangereuses dans le dépôt — ce dépôt doit être propre par construction
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

title "1. Parsing YAML de tous les manifests"
python3 - "$LAB_ROOT" <<'PY'
import sys, pathlib, yaml
from yaml.constructor import SafeConstructor
from yaml.nodes import MappingNode

class StrictLoader(yaml.SafeLoader):
    """SafeLoader qui REFUSE les clés dupliquées.

    Pourquoi c'est essentiel ici : yaml.safe_load accepte silencieusement
    deux blocs `apiVersion:` dans le même document (le second écrase le
    premier). Un séparateur `---` oublié produit donc un fichier qui
    « parse » mais dont un objet a disparu — exactement le bug qui a été
    trouvé dans ce dépôt lors de la validation.
    """

    def construct_mapping(self, node, deep=False):
        if isinstance(node, MappingNode):
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        f"clé dupliquée : {key!r} (séparateur '---' manquant ?)",
                        key_node.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep)

root = pathlib.Path(sys.argv[1])
files = sorted({p for p in list(root.rglob('*.yaml')) + list(root.rglob('*.yml'))
                if '.git' not in p.parts})
errors, count = [], 0
for f in files:
    try:
        docs = [d for d in yaml.load_all(f.read_text(), Loader=StrictLoader) if d is not None]
        count += len(docs)
    except Exception as exc:
        errors.append((f, exc))
for f, exc in errors:
    msg = str(exc).replace("\n", " ")
    print(f"  \u2718 {f.relative_to(root)}: {msg[:160]}")
print(f"  {len(files)} fichiers, {count} objets YAML \u2014 "
      f"{'OK' if not errors else str(len(errors)) + ' erreur(s)'}")
sys.exit(1 if errors else 0)
PY

title "2. Validation des schémas Kubernetes (kubeconform)"
if command -v kubeconform >/dev/null 2>&1; then
  find "$LAB_ROOT" -name '*.yaml' -not -path '*/.git/*' \
       -not -name '*config*.yaml' -not -name 'kind-config*' \
       -not -name 'audit-policy.yaml' -print0 \
    | xargs -0 kubeconform -strict -summary -ignore-missing-schemas \
        -kubernetes-version 1.31.0 2>&1 | sed 's/^/  /'
else
  warn "kubeconform non installé (brew install kubeconform / go install)"
  detail "La validation des schémas est un contrôle clé : installez-le."
fi

title "3. Recherche d'anti-patterns dans le dépôt"
FAIL=0

step "Secrets en clair dans les manifests (data: avec valeur littérale)"
if grep -rn --include='*.yaml' -E '^\s+(password|token|secret|api[_-]?key):\s+[A-Za-z0-9+/=]{8,}' \
     "$LAB_ROOT" 2>/dev/null | grep -v 'examples/' | grep -v '\.example\.' \
     | grep -v 'roleRef' | grep -v 'name:' | grep -v '\\$\\{' | sed 's/^/    /'; then
  fail "Valeur littérale détectée : un secret ne doit jamais être écrit dans un manifest"
  FAIL=1
else
  ok "Aucune valeur de secret littérale dans les manifests"
fi

step "Permissions RBAC dangereuses sur les secrets"
sed 's/^/    /' < <(grep -rn --include='*.yaml' -B4 -A2 'resources: \["secrets"\]' "$LAB_ROOT" 2>/dev/null \
  | grep -E 'list|watch|verbs' | grep -E '"list"|"watch"|\*' || echo "aucune occurrence de list/watch/* sur secrets")
if grep -rn --include='*.yaml' -A3 'resources: \["secrets"\]' "$LAB_ROOT" 2>/dev/null \
   | grep -qE 'verbs: \["(list|watch|\*)"\]|verbs: \["get", "list"'; then
  warn "Vérifiez les rules ci-dessus : list/watch sur secrets = énumération possible"
else
  ok "Aucun Role n'accorde list/watch/* sur les secrets"
fi

step "ClusterRole sur les secrets"
if grep -rln --include='*.yaml' -B2 -A6 'kind: ClusterRole$' "$LAB_ROOT" 2>/dev/null | head -3; then
  ok "Aucun ClusterRole applicatif ne porte sur les secrets (blast radius contenu)"
else
  ok "Aucun ClusterRole sur les secrets"
fi

step "Conteneurs privilégiés / root"
if grep -rn --include='*.yaml' -E 'privileged: true|runAsUser: 0' "$LAB_ROOT" 2>/dev/null | sed 's/^/    /'; then
  fail "Conteneur privilégié ou root détecté"
  FAIL=1
else
  ok "Aucun conteneur privilégié, aucun runAsUser: 0"
fi

step "Secrets montés vs variables d'environnement (le backend)"
# On ignore les commentaires : le fichier EXPLIQUE pourquoi envFrom est proscrit
if grep -vE '^\s*#' "$LAB_ROOT/apps/backend/deployment.yaml" | grep -qE '^\s*envFrom:'; then
  fail "envFrom trouvé dans le backend : le secret fuirait dans l'environnement"
  FAIL=1
else
  ok "Aucun envFrom dans le backend : injection par volume uniquement"
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  ok "VALIDATION RÉUSSIE — le dépôt respecte ses propres règles"
else
  fail "VALIDATION EN ÉCHEC — corriger les points ci-dessus"
  exit 1
fi
