#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Preuve d'application des NetworkPolicy — méthode du test de contrôle.
#
# Un test négatif seul ne prouve rien : il peut échouer pour une mauvaise
# raison (DNS, port fermé, Pod absent). On exige donc :
#   1. un contrôle POSITIF (un flux autorisé doit passer)
#   2. un test NÉGATIF (un flux interdit doit être bloqué)
#   3. la MÊME cible dans les deux cas, seul le chemin change
#
# Si le positif échoue, le test est NON CONCLUANT (et non « réussi »).
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster

title "Preuve d'application des NetworkPolicy"

POD="$(kubectl -n backend get pod -l app.kubernetes.io/name=api-backend -o jsonpath='{.items[0].metadata.name}')"

step "Contrôle positif : backend -> postgres:5432 (doit PASSSER)"
if kubectl -n backend exec "$POD" -- python -c '
import socket; socket.create_connection(("postgres.database.svc.cluster.local",5432),timeout=3)' 2>/dev/null; then
  POSITIVE=ok; ok "flux autorisé : opérationnel"
else
  POSITIVE=fail; fail "flux autorisé bloqué -> CNI ou politique trop stricte, test non concluant"
fi

step "Test négatif : backend -> vault:8200 (doit ÊTRE BLOQUÉ)"
if kubectl -n backend exec "$POD" -- python -c '
import socket; socket.create_connection(("vault.vault.svc.cluster.local",8200),timeout=3)' 2>/dev/null; then
  NEGATIVE=fail; fail "flux interdit PASSSE -> NetworkPolicy non appliquée par le CNI"
else
  NEGATIVE=ok; ok "flux interdit bloqué"
fi

printf '\n'
if [ "$POSITIVE" = ok ] && [ "$NEGATIVE" = ok ]; then
  ok "RÉSULTAT : les NetworkPolicy sont appliquées (et pas trop strictes)"
  exit 0
elif [ "$POSITIVE" = fail ]; then
  warn "NON CONCLUANT : vérifiez d'abord que les Pods backend et postgres tournent"
  detail "make status"
  exit 2
else
  fail "Les NetworkPolicy ne sont pas appliquées par le CNI actuel"
  detail "Correction : make install-calico  (recrée le cluster avec Calico)"
  exit 1
fi
