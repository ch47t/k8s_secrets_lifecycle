#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# (Optionnel) Installation de Calico pour que les NetworkPolicy soient
# RÉELLEMENT appliquées.
#
# kindnet (CNI par défaut de kind) accepte les NetworkPolicy sans les
# appliquer sur certaines versions. Résultat : la démonstration 5 « marche »
# sans rien prouver — c'est le pire cas pédagogique.
#
# Ce script recrée le cluster avec disableDefaultCNI: true et installe Calico.
# Coût : ~2 min de création, quelques centaines de Mo. À faire si vous voulez
# une démonstration réseau incontestable.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require kind kubectl

title "Recréation du cluster sans CNI par défaut"
CALICO_CFG="$LAB_ROOT/clusters/kind-config-calico.yaml"
sed -e "s|__LAB_ROOT__|${LAB_ROOT}|g" \
    -e 's|^kind: Cluster|kind: Cluster|' \
    "$LAB_ROOT/clusters/kind-config.yaml.tpl" > "$CALICO_CFG"
python3 - "$CALICO_CFG" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
s = s.rstrip() + "\nnetworking:\n  disableDefaultCNI: true\n  podSubnet: 192.168.0.0/16\n"
open(p, 'w').write(s)
PY
ok "Config générée : ${CALICO_CFG#"$LAB_ROOT"/} (disableDefaultCNI: true)"

warn "Le cluster va être SUPPRIMÉ et recréé (les données du lab sont perdues)"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
kind create cluster --config "$CALICO_CFG" --wait 240s

title "Installation de Calico (manifest officiel, tigera-operator)"
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/tigera-operator.yaml
step "Attente de l'opérateur"
kubectl -n tigera-operator rollout status deploy/tigera-operator --timeout=300s
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/custom-resources.yaml
step "Attente des nœuds prêts (Calico démarre les nœuds)"
kubectl wait --for=condition=Ready nodes --all --timeout=300s
kubectl -n calico-system rollout status ds/calico-node --timeout=300s || true

ok "Calico opérationnel : les NetworkPolicy sont maintenant appliquées"
cat <<'NEXT'

Étape suivante : reconstruire la plateforme
  make vault-eso
  make apps
  make demo-5-networkpolicy
NEXT
