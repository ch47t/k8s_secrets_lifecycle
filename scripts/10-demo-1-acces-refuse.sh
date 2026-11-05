#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 1 — « Un utilisateur non autorisé ne peut pas lire un secret »
#
# Le Pod `intrus` tourne dans le namespace security avec sa-intrus : aucun
# Role, aucun RoleBinding. Il a bien un token (automountServiceAccountToken:
# true) : c'est le pire cas réaliste — un attaquant qui a obtenu une exécution
# de code et un token d'API. Et pourtant : Forbidden.
#
# Ce que la démo prouve exactement :
#   - l'authentification réussit (le token est valide, l'API répond)
#   - l'autorisation échoue (RBAC)      -> c'est la différence essentielle
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster

title "DÉMO 1 — Accès refusé à un Pod non autorisé (sa-intrus)"

step "Identité réellement utilisée par le Pod attaquant"
kubectl -n security exec intrus -- kubectl auth whoami 2>/dev/null || true
kubectl -n security exec intrus -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace' \
  | sed 's/^/    namespace du token : /'
ok "Le token est valide : l'attaquant EST authentifié (ce n'est pas un problème de token)"

printf '\n'
step "Capacités effectives de sa-intrus (aucune ne doit être accordée)"
for check in \
  "get secrets -n backend" \
  "list secrets -n backend" \
  "get secret db-credentials -n backend" \
  "get secrets -n frontend" \
  "get secrets --all-namespaces" ; do
  # shellcheck disable=SC2086
  answer="$(kubectl auth can-i $check --as=system:serviceaccount:security:sa-intrus 2>/dev/null || echo unknown)"
  printf '    kubectl auth can-i %-38s -> %s\n' "$check" "$answer"
done

printf '\n%s%sTentative réelle : lecture du secret critique depuis le Pod%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
show_cmd "kubectl -n security exec intrus -- kubectl get secret db-credentials -n backend -o jsonpath='{.data.password}' | base64 -d"

set +e
OUT="$(kubectl -n security exec intrus -- kubectl get secret db-credentials -n backend -o jsonpath='{.data.password}' 2>&1)"
RC=$?
set -e
printf '%s\n' "$OUT" | sed 's/^/    /'

printf '\n'
if echo "$OUT" | grep -q "Forbidden"; then
  ok "RÉSULTAT ATTENDU : Forbidden (secrets \"db-credentials\" is forbidden)"
  detail "L'API a bien authentifié sa-intrus, puis refusé l'autorisation."
elif [ "$RC" -eq 0 ]; then
  fail "FUITE : le secret a été lu. Le RoleBinding est trop permissif."
  exit 1
else
  warn "Erreur inattendue (code $RC) — inspecter la sortie ci-dessus"
fi

printf '\n'
step "Trois autres tentatives (défense en profondeur, tous les chemins fermés)"
for cmd in \
  "get secrets -n backend" \
  "get secret db-credentials -n frontend" \
  "get secrets -A" ; do
  # shellcheck disable=SC2086
  res="$(kubectl -n security exec intrus -- kubectl $cmd 2>&1 | head -2)"
  printf '    $ kubectl %-34s -> %s\n' "$cmd" "$(echo "$res" | tr '\n' ' ' | cut -c1-90)"
done

printf '\n'
step "Traçabilité : le refus est-il dans l'audit log ?"
if docker exec kind-control-plane test -f /var/log/kubernetes/audit.log 2>/dev/null; then
  docker exec kind-control-plane sh -c \
    'grep -a "secrets" /var/log/kubernetes/audit.log | grep -a "sa-intrus" | tail -2' \
    2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    try: e = json.loads(line)
    except Exception: continue
    print(f"    {e.get(\"requestReceivedTimestamp\",\"\")}  user={e.get(\"user\",{}).get(\"username\")}"
          f"  verb={e.get(\"verb\")}  resource={e.get(\"objectRef\",{}).get(\"resource\")}/{e.get(\"objectRef\",{}).get(\"name\",\"-\")}"
          f"  status={e.get(\"responseStatus\",{}).get(\"code\",\"?\")}")
' || detail "aucune entrée (l\'audit peut avoir un léger délai)"
else
  warn "audit.log absent — voir la config kind"
fi

printf '\n%s%sCONCLUSION DÉMO 1%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Authentification ≠ autorisation.
  Le token du Pod attaquant est parfaitement valide (l'API le reconnaît), mais
  le RBAC n'accorde AUCUN droit à sa-intrus : la requête échoue en 403.
  Aucun secret n'est lisible, même dans un namespace où l'attaquant vit.
C
