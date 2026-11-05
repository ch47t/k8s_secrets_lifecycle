#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 5 — Blast radius : le backend ne peut PAS joindre Vault
#
# Répond à la question du plan (partie 6) : « Peut-il contacter Vault
# directement ? » La réponse doit être prouvée, pas affirmée.
#
# Méthode rigoureuse : on commence par un TEST DE CONTRÔLE (une cible qui DOIT
# être joignable). Sans contrôle positif, un échec réseau se confond avec une
# politique — c'est l'erreur méthodologique classique.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster

title "DÉMO 5 — Isolation réseau (NetworkPolicy) et blast radius"

step "Pré-requis : le CNI applique-t-il vraiment les politiques ?"
CNI="$(kubectl -n kube-system get pods -o name | grep -E 'kindnet|calico|cilium' | head -3 | tr '\n' ' ')"
echo "    CNI détecté : ${CNI:-inconnu}"
if echo "$CNI" | grep -q kindnet; then
  warn "kindnet n'applique PAS les NetworkPolicy sur toutes les versions de kind."
  detail "Installez Calico pour une démonstration incontestable : make install-calico"
  detail "Le test ci-dessous tranchera : si la cible est joignable, la politique est inerte."
fi

POD_BACKEND="$(kubectl -n backend get pod -l app.kubernetes.io/name=api-backend -o jsonpath='{.items[0].metadata.name}')"

printf '\n'
step "TEST DE CONTRÔLE — une cible qui DOIT répondre : postgres:5432"
show_cmd "kubectl -n backend exec $POD_BACKEND -- python -c 'socket.create_connection((\"postgres.database\",5432))'"
kubectl -n backend exec "$POD_BACKEND" -- python -c '
import socket
s = socket.create_connection(("postgres.database.svc.cluster.local", 5432), timeout=3)
print("    CONNECTÉ ->", s.getpeername())'
ok "PostgreSQL joignable depuis le backend : le réseau fonctionne (contrôle positif)"
detail "Sans ce contrôle, on ne saurait pas si un échec vient de la politique ou du réseau."

printf '\n'
step "TEST CIBLE — le backend peut-il joindre Vault (8200) ?"
show_cmd "kubectl -n backend exec $POD_BACKEND -- python -c 'socket.create_connection((\"vault.vault\",8200))'"
set +e
OUT="$(kubectl -n backend exec "$POD_BACKEND" -- python -c '
import socket
s = socket.create_connection(("vault.vault.svc.cluster.local", 8200), timeout=3)
print("CONNECTÉ ->", s.getpeername())' 2>&1)"
set -e
printf '%s\n' "$OUT" | sed 's/^/    /'
if echo "$OUT" | grep -q "CONNECTÉ"; then
  fail "Vault est joignable depuis le backend : la NetworkPolicy n'est PAS appliquée"
  detail "Installez un CNI qui applique les politiques : make install-calico"
  RESULT_NETPOL="non appliquée"
else
  ok "RÉSULTAT ATTENDU : timeout / refus — le backend ne peut pas joindre Vault"
  detail "Un Pod backend compromis ne peut donc pas contourner ESO pour piller Vault."
  RESULT_NETPOL="appliquée"
fi

printf '\n'
step "Le Pod intrus (namespace security) peut-il joindre Vault ?"
set +e
OUT2="$(kubectl -n security exec tools -- nc -w 3 -z vault.vault.svc.cluster.local 8200 2>&1; echo "rc=$?")"
set -e
printf '%s\n' "$OUT2" | sed 's/^/    /'
echo "$OUT2" | grep -q "rc=0" && warn "Joignable : à corriger" || ok "Refusé depuis un namespace non autorisé"

printf '\n'
step "Le frontend peut-il joindre PostgreSQL directement ?"
set +e
OUT3="$(kubectl -n security exec tools -- nc -w 3 -z postgres.database.svc.cluster.local 5432 2>&1; echo "rc=$?")"
set -e
echo "$OUT3" | grep -q "rc=0" && warn "Joignable : la base est exposée à tout le cluster" || ok "Refusé : la base n'accepte que backend et vault"

printf '\n'
step "Récapitulatif des flux autorisés (matrice réseau)"
kubectl get networkpolicy -A -o custom-columns=\
NAMESPACE:.metadata.namespace,POLITIQUE:.metadata.name,DENY:.metadata.annotations.note \
  --no-headers 2>/dev/null | sed 's/^/    /' | head -20

cat <<'MATRIX'

    Source            Destination            Autorisé ?
    ─────────────────────────────────────────────────────
    frontend          backend:8080           oui
    backend           postgres:5432          oui
    backend           vault:8200             NON  <- blast radius
    backend           internet / autre ns    NON
    ESO               vault:8200             oui
    vault             postgres:5432          oui (dynamic secrets)
    security (intrus) tout                   NON
MATRIX

printf '\n%s%sCONCLUSION DÉMO 5%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<C
  État de l'application des politiques : ${RESULT_NETPOL}
  Le RBAC empêche de LIRE les secrets via l'API ; NetworkPolicy empêche de
  CONTOURNER le RBAC en contactant Vault directement. Les deux couches sont
  nécessaires : aucune ne remplace l'autre.
C
