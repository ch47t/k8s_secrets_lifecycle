#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 7 — Un utilisateur HUMAIN non autorisé (certificat client)
#
# Le plan parle de « compte non autorisé ». Un Pod n'est qu'un cas : le plus
# fréquent est le développeur avec un kubeconfig trop large.
#
# On génère un certificat client signé par la CA du cluster kind :
#     CN = alice, O = developers
# puis on teste trois choses :
#   - lecture de jwt-key        -> autorisée (le Role du groupe developers)
#   - lecture de db-credentials -> refusée (le secret critique)
#   - kubectl get secrets (list)-> refusé (impossible d'énumérer)
#
# Aucune clé privée n'est committée : tout est généré dans /tmp puis supprimé.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster
require docker openssl

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

title "DÉMO 7 — Utilisateur humain non autorisé (CN=alice, O=developers)"

step "1. Récupération de l'autorité de certification du cluster (nœud kind)"
docker exec kind-control-plane cat /etc/kubernetes/pki/ca.crt > "$WORKDIR/ca.crt"
docker exec kind-control-plane cat /etc/kubernetes/pki/ca.key > "$WORKDIR/ca.key"
ok "CA récupérée (possible uniquement parce que nous contrôlons le nœud : c'est du lab)"

step "2. Génération de la clé privée et de la demande de certificat d'alice"
openssl genrsa -out "$WORKDIR/alice.key" 2048 2>/dev/null
openssl req -new -key "$WORKDIR/alice.key" -out "$WORKDIR/alice.csr" \
  -subj "/CN=alice/O=developers" 2>/dev/null
openssl x509 -req -in "$WORKDIR/alice.csr" -CA "$WORKDIR/ca.crt" -CAkey "$WORKDIR/ca.key" \
  -CAcreateserial -out "$WORKDIR/alice.crt" -days 1 2>/dev/null
ok "Certificat client signé (validité 1 jour, durée volontairement courte)"

step "3. Construction d'un kubeconfig dédié (celui d'alice, pas le nôtre)"
APISERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config set-cluster kind-secrets-lab --server="$APISERVER" \
  --certificate-authority="$WORKDIR/ca.crt" --embed-certs=true \
  --kubeconfig="$WORKDIR/alice.kubeconfig" >/dev/null
kubectl config set-credentials alice \
  --client-certificate="$WORKDIR/alice.crt" --client-key="$WORKDIR/alice.key" --embed-certs=true \
  --kubeconfig="$WORKDIR/alice.kubeconfig" >/dev/null
kubectl config set-context alice --cluster=kind-secrets-lab --user=alice \
  --kubeconfig="$WORKDIR/alice.kubeconfig" >/dev/null
kubectl config use-context alice --kubeconfig="$WORKDIR/alice.kubeconfig" >/dev/null

echo "    Identité vue par l'API :"
kubectl --kubeconfig="$WORKDIR/alice.kubeconfig" auth whoami 2>/dev/null | sed 's/^/      /' \
  || echo "      (auth whoami indisponible sur cette version)"

printf '\n'
step "4. Ce qu'alice PEUT faire (rôle du groupe developers)"
set +e
OUT1="$(kubectl --kubeconfig="$WORKDIR/alice.kubeconfig" -n backend get secret jwt-key -o name 2>&1)"
RC1=$?
set -e
printf '%s\n' "$OUT1" | sed 's/^/    /'
[ "$RC1" -eq 0 ] && ok "get secret jwt-key -> autorisé (usage de debug légitime)" \
  || warn "Refusé : le RoleBinding du groupe developers est-il appliqué ?"

printf '\n'
step "5. Ce qu'alice NE PEUT PAS faire"
for cmd in \
  "get secret db-credentials" \
  "get secret external-api-key" \
  "get secrets" \
  "get secrets -n frontend" ; do
  set +e
  # shellcheck disable=SC2086
  res="$(kubectl --kubeconfig="$WORKDIR/alice.kubeconfig" -n backend $cmd 2>&1 | head -1)"
  set -e
  if echo "$res" | grep -q "Forbidden"; then
    printf '    %-32s -> %sForbidden%s\n' "kubectl $cmd" "$C_GREEN" "$C_RESET"
  else
    printf '    %-32s -> %s\n' "kubectl $cmd" "$(echo "$res" | cut -c1-70)"
  fi
done

printf '\n'
step "6. Tentative de lecture du secret critique, pour la forme"
set +e
OUT2="$(kubectl --kubeconfig="$WORKDIR/alice.kubeconfig" -n backend \
  get secret db-credentials -o jsonpath='{.data.password}' 2>&1)"
set -e
printf '%s\n' "$OUT2" | sed 's/^/    /'
echo "$OUT2" | grep -q Forbidden && ok "RÉSULTAT ATTENDU : Forbidden pour un humain aussi" \
  || fail "Un humain non autorisé a pu lire le secret critique"

printf '\n'
step "7. Audit : la tentative est-elle tracée ?"
if docker exec kind-control-plane test -f /var/log/kubernetes/audit.log 2>/dev/null; then
  docker exec kind-control-plane sh -c 'grep -a "alice" /var/log/kubernetes/audit.log | tail -3' 2>/dev/null \
    | python3 -c '
import sys, json
for line in sys.stdin:
    try: e = json.loads(line)
    except Exception: continue
    print(f"    user={e.get(\"user\",{}).get(\"username\")} verb={e.get(\"verb\")} "
          f"secret={e.get(\"objectRef\",{}).get(\"name\",\"-\")} code={e.get(\"responseStatus\",{}).get(\"code\",\"?\")}")
' || detail "pas d'entrée (délai d'écriture du log d'audit)"
fi

rm -f "$WORKDIR/ca.key"   # la clé de la CA ne doit jamais rester sur disque

printf '\n%s%sCONCLUSION DÉMO 7%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Le moindre privilège s'applique aussi aux humains. Un certificat valide ne
  donne aucun droit : c'est le RoleBinding (groupe developers) qui accorde
  exactement UNE lecture nominative. Le secret critique reste inaccessible,
  et l'identité de la tentative est dans l'audit log.
C
C
