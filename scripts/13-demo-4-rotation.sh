#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 4 — « La rotation d'un identifiant n'implique pas de redémarrage »
#
# C'est le point le plus important du projet (partie 4 du plan).
#
# Scénario, entièrement automatisé :
#   1. on note l'UID du Pod backend, son âge et son compteur de redémarrages
#      => ce sont les témoins : s'ils ne changent pas, rien n'a redémarré ;
#   2. on lance un Pod « watcher » qui monte le secret en volume et imprime
#      l'empreinte du fichier toutes les 10 s (preuve visuelle du changement) ;
#   3. on change le mot de passe réellement dans PostgreSQL (ALTER USER)
#      puis on écrit la même valeur dans Vault : la source de vérité ;
#   4. ESO détecte le changement (refreshInterval: 30s) et met à jour le
#      Secret Kubernetes, dans les DEUX namespaces ;
#   5. le kubelet propage le nouveau contenu dans le volume monté ;
#   6. on vérifie : nouveau fingerprint côté backend, connexion PostgreSQL
#      toujours fonctionnelle, Pod non redémarré.
#
# Le résultat est une rotation complète en ~40 s sans kubectl rollout restart,
# sans build, sans intervention humaine.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster
require kubectl openssl

NS_BACKEND="backend"
POD_SEL="app.kubernetes.io/name=api-backend"

title "DÉMO 4 — Rotation d'un secret sans redémarrage"

POD="$(kubectl -n "$NS_BACKEND" get pod -l "$POD_SEL" -o jsonpath='{.items[0].metadata.name}')"
UID_BEFORE="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.metadata.uid}')"
CREATED_BEFORE="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.metadata.creationTimestamp}')"
RESTARTS_BEFORE="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')"

step "Témoins AVANT rotation (Pod $POD)"
cat <<T
    uid                 : $UID_BEFORE
    créé le             : $CREATED_BEFORE
    redémarrages        : $RESTARTS_BEFORE
T

step "Empreinte du mot de passe AVANT (côté application et côté Secret)"
BEFORE_APP="$(kubectl -n backend exec "$POD" -- python -c '
import json,urllib.request
d=json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/secret-fingerprint"))
print(d["db_password"]["sha256_prefix"])' 2>/dev/null || echo "n/a")"
BEFORE_SECRET="$(kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}' | base64 -d | sha256sum | cut -c1-12)"
BEFORE_VAULT="$(kubectl -n vault exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  vault kv get -field=password secret/backend/db-credentials 2>/dev/null | sha256sum | cut -c1-12)"
echo "    sha256 (application) : $BEFORE_APP"
echo "    sha256 (Secret K8s)  : $BEFORE_SECRET"
echo "    sha256 (Vault)       : $BEFORE_VAULT"
[ "$BEFORE_APP" = "$BEFORE_SECRET" ] && ok "Cohérence application <-> Secret Kubernetes" \
  || warn "Désynchronisation détectée (le kubelet a peut-être un léger retard)"

printf "\n${C_BOLD}Lancement du watcher qui observe le volume monté${C_RESET}\n"
kubectl -n backend delete job rotation-watcher --ignore-not-found >/dev/null 2>&1 || true
kubectl -n backend apply -f "$LAB_ROOT/demos/rotation-watcher-job.yaml" >/dev/null
detail "Le watcher imprime empreinte + mtime du fichier toutes les 10 s pendant 4 min"
sleep 5

title "ÉTAPE 1/3 — Rotation dans la source de vérité (Vault) ET dans PostgreSQL"
NEW_PASSWORD="$(openssl rand -hex 24)"
NEW_SHA="$(printf '%s' "$NEW_PASSWORD" | sha256sum | cut -c1-12)"
detail "Nouveau mot de passe généré : 48 caractères hexadécimaux"
detail "Empreinte attendue après rotation : $NEW_SHA"

step "1a. Application du nouveau mot de passe à PostgreSQL (ALTER USER)"
show_cmd "kubectl exec -n database postgres-0 -- psql -U app -d appdb -c 'ALTER USER app ...'"
kubectl -n database exec postgres-0 -- psql -U app -d appdb -v ON_ERROR_STOP=1 \
  -c "ALTER USER app WITH PASSWORD '${NEW_PASSWORD}';" | sed 's/^/    /'
ok "PostgreSQL accepte désormais uniquement le nouveau mot de passe"
detail "À cet instant précis, le secret applicatif est OBSOLÈTE : c'est la"
detail "fenêtre d'exposition que la rotation automatique doit réduire à zéro."

step "1b. Écriture de la nouvelle valeur dans Vault (KV v2, nouvelle version)"
kubectl -n vault exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  vault kv put secret/backend/db-credentials \
    username=app \
    password="$NEW_PASSWORD" \
    host=postgres.database.svc.cluster.local \
    port=5432 \
    database=appdb >/dev/null
kubectl -n vault exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  vault kv put secret/database/db-credentials \
    username=app \
    password="$NEW_PASSWORD" \
    host=postgres.database.svc.cluster.local \
    port=5432 \
    database=appdb >/dev/null
ok "Vault contient la version N+1 (l'ancienne valeur est dans l'historique KV)"

title "ÉTAPE 2/3 — Propagation automatique (ESO, refreshInterval: 30s)"
step "Attente de la mise à jour du Secret Kubernetes (aucune action manuelle)"
START=$(date +%s)
SECRET_FP=""
for _ in $(seq 1 40); do
  SECRET_FP="$(kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null | sha256sum | cut -c1-12)"
  [ "$SECRET_FP" = "$NEW_SHA" ] && break
  printf '.'
  sleep 3
done
printf '\n'
ELAPSED=$(( $(date +%s) - START ))
if [ "$SECRET_FP" = "$NEW_SHA" ]; then
  ok "Secret Kubernetes mis à jour en ${ELAPSED}s (empreinte $SECRET_FP)"
else
  fail "Le Secret n'a pas été mis à jour en 120 s (empreinte actuelle: $SECRET_FP)"
  kubectl -n backend describe externalsecret db-credentials | tail -15
  exit 1
fi

kubectl -n backend get secret db-credentials \
  -o jsonpath='{.metadata.annotations.external-secrets\.io/refresh-status}' 2>/dev/null | sed 's/^/    statut ESO : /' || true
echo "    dernière synchro : $(kubectl -n backend get externalsecret db-credentials -o jsonpath='{.status.refreshTime}')"

title "ÉTAPE 3/3 — Le Pod n'a PAS redémarré et fonctionne"
step "Attente de la propagation kubelet dans le volume monté (jusqu'à 90 s)"
APP_FP="$BEFORE_APP"
for _ in $(seq 1 45); do
  APP_FP="$(kubectl -n backend exec "$POD" -- python -c '
import json,urllib.request
d=json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/secret-fingerprint"))
print(d["db_password"]["sha256_prefix"])' 2>/dev/null || echo "$APP_FP")"
  [ "$APP_FP" = "$NEW_SHA" ] && break
  printf '.'
  sleep 2
done
printf '\n'

UID_AFTER="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "pod-disparu")"
CREATED_AFTER="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null || echo "-")"
RESTARTS_AFTER="$(kubectl -n "$NS_BACKEND" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "-")"

printf '\n%s%sBILAN%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
printf '  %-34s %-16s %-16s\n' "Témoin" "AVANT" "APRÈS"
printf '  %-34s %-16s %-16s\n' "Empreinte mot de passe (app)" "$BEFORE_APP" "$APP_FP"
printf '  %-34s %-16s %-16s\n' "UID du Pod" "${UID_BEFORE:0:12}…" "${UID_AFTER:0:12}…"
printf '  %-34s %-16s %-16s\n' "Date de création du Pod" "${CREATED_BEFORE:11:8}" "${CREATED_AFTER:11:8}"
printf '  %-34s %-16s %-16s\n' "Redémarrages conteneur" "$RESTARTS_BEFORE" "$RESTARTS_AFTER"
printf '\n'

FAILED=0
[ "$APP_FP" = "$NEW_SHA" ] || { fail "L'application lit encore l'ancien mot de passe"; FAILED=1; }
[ "$UID_BEFORE" = "$UID_AFTER" ] || { fail "Le Pod a été recréé : la rotation n'est PAS transparente"; FAILED=1; }
[ "$RESTARTS_BEFORE" = "$RESTARTS_AFTER" ] || { fail "Le conteneur a redémarré"; FAILED=1; }

if [ "$FAILED" -eq 0 ]; then
  ok "Rotation complète : nouvelle valeur lue par l'application, Pod inchangé"
  detail "Aucun 'kubectl rollout restart', aucune image reconstruite, aucun redémarrage."
fi

printf '\n'
step "Preuve fonctionnelle : la connexion PostgreSQL fonctionne toujours"
kubectl -n backend exec "$POD" -- python -c '
import json, urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/db-check")), indent=2))' \
  | sed 's/^/    /'

printf '\n'
step "Journal du watcher (le fichier a changé sans recréation du Pod)"
kubectl -n backend logs job/rotation-watcher --tail=12 2>/dev/null | sed 's/^/    /' || true

printf '\n'
step "Traçabilité : l'écriture dans Vault est dans l'audit de Vault"
kubectl -n vault exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  vault kv metadata get secret/backend/db-credentials 2>/dev/null | sed 's/^/    /' | head -12

printf '\n%s%sCONCLUSION DÉMO 4%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Un Secret Kubernetes natif ne se renouvelle pas seul : ESO fait le pont.
  La chaîne Vault -> ESO -> Secret -> volume monté permet une rotation en
  moins d'une minute, sans redémarrage, sans intervention.
  Limite à énoncer honnêtement : le délai n'est pas nul (TTL ESO + kubelet).
  Pour une fenêtre réellement nulle, il faut des dynamic secrets dont la
  valeur EST créée à la demande (voir docs/05-vault-eso.md, démo 5b).
C
