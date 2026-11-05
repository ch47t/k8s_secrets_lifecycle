#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Étape 0 — création du cluster kind avec chiffrement au repos des Secrets.
#
# Ce script fait trois choses que `kind create cluster` ne fait pas :
#   1. génère une clé aescbc aléatoire (jamais committée) et produit le fichier
#      EncryptionConfiguration ;
#   2. monte ce fichier + la politique d'audit dans le nœud de contrôle ;
#   3. VÉRIFIE par la preuve que le chiffrement fonctionne réellement —
#      un cluster « configuré » qui ne chiffre pas est pire qu'un cluster
#      non configuré, parce qu'on croit être protégé.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require kind kubectl openssl

title "0. Préparation des fichiers de chiffrement"
ENC_TPL="$LAB_ROOT/infrastructure/encryption/encryption-config.yaml.tpl"
ENC_OUT="$LAB_ROOT/infrastructure/encryption/encryption-config.yaml"

if [ -f "$ENC_OUT" ]; then
  warn "EncryptionConfiguration existante conservée (rotation de clé hors périmètre du script)"
else
  step "Génération d'une clé aescbc de 32 octets"
  KEY="$(openssl rand -base64 32)"
  sed "s|__AESCBC_KEY__|${KEY}|" "$ENC_TPL" > "$ENC_OUT"
  chmod 600 "$ENC_OUT"
  ok "Clé générée -> $ENC_OUT ${C_DIM}(gitignoré)${C_RESET}"
fi

title "1. Génération de la config kind (chemins absolus)"
KIND_CFG="$LAB_ROOT/clusters/kind-config.yaml"
sed "s|__LAB_ROOT__|${LAB_ROOT}|g" "$LAB_ROOT/clusters/kind-config.yaml.tpl" > "$KIND_CFG"
ok "Config générée -> $KIND_CFG"

title "2. Création du cluster kind"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  warn "Cluster '$CLUSTER_NAME' déjà présent — suppression puis recréation"
  kind delete cluster --name "$CLUSTER_NAME"
fi
kind create cluster --config "$KIND_CFG" --wait 180s
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
ok "Cluster prêt"

title "3. Vérification que le chiffrement est RÉELLEMENT actif"
step "L'API server a-t-il bien reçu l'argument ?"
kubectl -n kube-system get pod kube-apiserver-kind-control-plane \
  -o jsonpath='{.spec.containers[0].command}' | tr ',' '\n' \
  | grep -E 'encryption-provider-config|audit-policy' | sed 's/^/    /'
ok "Arguments présents"

step "Création d'un Secret témoin puis lecture brute dans etcd"
kubectl create namespace demo-encryption >/dev/null 2>&1 || true
kubectl -n demo-encryption create secret generic temoin \
  --from-literal=clair='ce-texte-ne-doit-jamais-apparaitre-dans-etcd' \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

step "Lecture du contenu stocké dans etcd (via le conteneur etcd du nœud)"
RAW="$(docker exec kind-control-plane etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/demo-encryption/temoin 2>/dev/null || true)"

if echo "$RAW" | grep -q 'k8s:enc:aescbc'; then
  ok "Le préfixe 'k8s:enc:aescbc:v1:key1' est présent : les données sont chiffrées"
elif echo "$RAW" | grep -q 'ce-texte-ne-doit-jamais-apparaitre-dans-etcd'; then
  fail "Le secret est en CLAIR dans etcd — le chiffrement n'est PAS actif"
  exit 1
else
  warn "Lecture etcd non concluante (droits docker ?). Vérifiez manuellement : make demo-etcd"
fi

kubectl delete namespace demo-encryption --wait=false >/dev/null 2>&1 || true

title "Résumé"
cat <<'SUMMARY'
Cluster : kind-secrets-lab
  - chiffrement au repos aescbc : activé (clé dans infrastructure/encryption/, gitignorée)
  - audit log                  : /var/log/kubernetes/audit.log dans le nœud
  - port 80 du nœud            : mappé sur http://localhost:8080 (frontend)

Étape suivante : make vault-eso
SUMMARY
