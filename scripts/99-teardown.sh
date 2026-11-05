#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Destruction complète du lab.
#
# Ordre volontaire : on supprime le cluster AVANT les fichiers générés, parce
# que la clé de chiffrement etcd doit être détruite avec lui — la laisser
# traîner sur un disque n'a aucun intérêt et constitue un risque.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

title "Suppression du cluster kind"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  kind delete cluster --name "$CLUSTER_NAME"
  ok "Cluster '$CLUSTER_NAME' supprimé"
else
  warn "Cluster '$CLUSTER_NAME' absent"
fi

title "Suppression des fichiers générés (non versionnés)"
for f in \
  "$LAB_ROOT/infrastructure/encryption/encryption-config.yaml" \
  "$LAB_ROOT/clusters/kind-config.yaml" ; do
  if [ -f "$f" ]; then
    shred -u "$f" 2>/dev/null || rm -f "$f"
    ok "Supprimé : ${f#"$LAB_ROOT"/}"
  fi
done

step "Images Docker locales (facultatif)"
detail "docker rmi secrets-lab/api-backend:1.0.0"
detail "docker exec kind-control-plane ... (supprimé avec le cluster)"

cat <<'END'

Le dépôt reste intact : il ne contenait aucun secret.
C'est précisément le résultat attendu — un `make teardown` ne doit jamais
avoir à « nettoyer » des credentials, puisque le dépôt n'en a jamais eu.
END
