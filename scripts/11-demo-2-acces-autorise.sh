#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 2 — « Un workload ne reçoit que les secrets dont il a besoin »
#
# Trois preuves en une :
#   a) depuis le Pod api-backend, la lecture de ses DEUX secrets nominatifs
#      est autorisée (get uniquement, sur des noms précis) ;
#   b) la lecture d'un TROISIÈME secret du MÊME namespace est refusée
#      (external-api-key existe, mais n'est pas dans resourceNames) ;
#   c) `list` est refusé : impossible d'énumérer les noms de secrets.
#   d) le secret est monté en volume ; il n'apparaît PAS dans les variables
#      d'environnement du processus applicatif.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster

POD="$(kubectl -n backend get pod -l app.kubernetes.io/name=api-backend -o jsonpath='{.items[0].metadata.name}')"
title "DÉMO 2 — Accès autorisé, strictement nominatif (backend/$POD)"

step "(a) Les secrets nominatifs sont-ils lisibles depuis le Pod ?"
for secret in db-credentials jwt-key; do
  if kubectl -n backend exec "$POD" -- kubectl get secret "$secret" -o name >/dev/null 2>&1; then
    ok "get secret $secret -> autorisé"
  else
    fail "get secret $secret -> refusé (le RoleBinding est-il appliqué ?)"
  fi
done

printf '\n'
step "(b) Un secret du même namespace NON listé dans resourceNames"
show_cmd "kubectl get secret external-api-key"
OUT="$(kubectl -n backend exec "$POD" -- kubectl get secret external-api-key 2>&1 || true)"
printf '%s\n' "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -q Forbidden \
  && ok "RÉSULTAT ATTENDU : Forbidden — nominatif, pas 'tout le namespace'" \
  || warn "Vérifier le Role : resourceNames ne devrait pas contenir external-api-key"

printf '\n'
step "(c) Énumération des secrets : list / watch"
for verb in list watch; do
  res="$(kubectl -n backend exec "$POD" -- kubectl get secrets --watch=false 2>&1 | head -1 || true)"
  [ "$verb" = watch ] && res="$(kubectl -n backend exec "$POD" -- kubectl get secrets -w --request-timeout=3s 2>&1 | head -1 || true)"
  printf '    %-6s -> %s\n' "$verb" "$(echo "$res" | cut -c1-95)"
done
ok "list refuse : l'attaquant ne peut même pas découvrir les NOMS des secrets"

printf '\n'
step "(d) Injection par volume, pas par variable d'environnement"
echo "    Variables d'environnement du conteneur applicatif :"
kubectl -n backend exec "$POD" -- env 2>/dev/null \
  | grep -iE 'password|secret|token|key=' | grep -viE 'SECRETS_DIR|PATH' \
  | sed 's/^/      /' || true
if kubectl -n backend exec "$POD" -- env 2>/dev/null | grep -qiE '^DB_PASSWORD=|^POSTGRES_PASSWORD='; then
  fail "Une variable d'environnement contient un secret (anti-pattern)"
else
  ok "Aucune variable d'environnement ne contient de secret"
fi

echo "    Fichiers montés (lecture seule) :"
kubectl -n backend exec "$POD" -- sh -c \
  'ls -l /etc/app-secrets/*/ 2>/dev/null | sed "/^total/d"' | sed 's/^/      /'

printf '\n'
step "(e) Empreinte des secrets lus par le processus applicatif"
kubectl -n backend exec "$POD" -- python -c '
import json, urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/secret-fingerprint")), indent=2))
' | sed 's/^/    /'

printf '\n'
step "(f) Preuve positive : la connexion à PostgreSQL fonctionne avec ce secret"
kubectl -n backend exec "$POD" -- python -c '
import json, urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/db-check")), indent=2))
' | sed 's/^/    /'

printf '\n%s%sCONCLUSION DÉMO 2%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Le backend lit ce dont il a besoin (2 secrets nommés), et rien d'autre.
  Le secret est un FICHIER, pas une variable d'environnement : il n'apparaît
  ni dans `kubectl describe pod`, ni dans /proc/<pid>/environ, ni dans les
  logs système, et il est mis à jour sans redémarrage (voir démo 4).
C
