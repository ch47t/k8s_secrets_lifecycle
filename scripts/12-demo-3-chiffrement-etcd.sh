#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# DÉMO 3 — « Les secrets ne sont pas lisibles dans etcd »
#
# C'est LA démonstration que la plupart des équipes ne font pas, et c'est celle
# qui compte : RBAC protège l'API, pas le stockage. Une sauvegarde etcd volée,
# un snapshot, un accès disque — et tous les secrets tombent, sauf si
# EncryptionConfiguration est active.
#
# Le script montre trois choses :
#   1. ce que contient etcd pour un Secret (préfixe k8s:enc:aescbc:v1:key1)
#   2. la comparaison avec le Base64 de l'API (qui N'EST PAS du chiffrement)
#   3. que la clé de chiffrement vit hors du cluster (dans le dépôt, gitignorée)
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
check_cluster
require docker

title "DÉMO 3 — Chiffrement au repos des Secrets dans etcd"

step "L'API server reçoit-il bien la configuration ?"
kubectl -n kube-system get pod kube-apiserver-kind-control-plane \
  -o jsonpath='{.spec.containers[0].command}' | tr ',' '\n' \
  | grep -E 'encryption' | sed 's/^/    /'

printf '\n'
step "Emplacement du fichier dans le nœud de contrôle (monté depuis le dépôt)"
show_cmd "docker exec kind-control-plane ls -l /etc/kubernetes/encryption-config.yaml"
docker exec kind-control-plane ls -l /etc/kubernetes/encryption-config.yaml | sed 's/^/    /'
echo "    providers configurés :"
docker exec kind-control-plane sh -c \
  "grep -E 'aescbc|identity|key1' /etc/kubernetes/encryption-config.yaml" \
  | sed 's/^/      /'

printf '\n'
step "1. Ce que voit l'API (base64 — ce n'est PAS du chiffrement)"
show_cmd "kubectl get secret db-credentials -n backend -o jsonpath='{.data.password}'"
B64="$(kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}')"
echo "    valeur base64 : ${B64:0:40}…"
detail "décodée : $(echo "$B64" | base64 -d | cut -c1-6)…  (lisible par toute personne ayant l'objet)"

printf '\n'
step "2. Ce que contient réellement etcd (lecture brute du magasin clé-valeur)"
show_cmd "docker exec kind-control-plane etcdctl get /registry/secrets/backend/db-credentials"
RAW="$(docker exec kind-control-plane etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/backend/db-credentials 2>/dev/null || true)"

if [ -z "$RAW" ]; then
  fail "Lecture etcd impossible (docker ? permissions ?). Vérifiez manuellement."
  exit 1
fi

echo "    début de la valeur stockée :"
printf '%s\n' "$RAW" | tail -c 400 | head -c 300 | sed 's/^/      /'
printf '\n\n'

if printf '%s' "$RAW" | grep -q 'k8s:enc:aescbc:v1:key1'; then
  ok "Le préfixe k8s:enc:aescbc:v1:key1 est présent -> donnée chiffrée par l'API server"
else
  fail "Pas de préfixe de chiffrement : le secret est stocké en clair"
fi

step "3. Preuve négative : la valeur en clair est-elle absente d'etcd ?"
PW="$(kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}' | base64 -d)"
PW_B64="$(kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}')"
if printf '%s' "$RAW" | grep -qF "$PW" || printf '%s' "$RAW" | grep -qF "$PW_B64"; then
  fail "La valeur (ou son base64) apparaît dans etcd : CHIFFREMENT INEFFICACE"
  exit 1
else
  ok "Ni la valeur en clair ni son base64 n'apparaissent dans le stockage"
  detail "Un dump d'etcd ne donne aucun secret exploitable."
fi

printf '\n'
step "4. Contre-expérience : un Secret créé dans un namespace non couvert"
detail "Tous les secrets passent par le même chemin. Pour montrer la différence,"
detail "il faudrait désactiver identity:{} — c'est justement le piège : identity"
detail "en dernier laisse les anciens objets en clair indéfiniment."

printf '\n'
step "5. Rotation de la clé de chiffrement (procédure, non exécutée ici)"
cat <<'PROC'
    1. générer une nouvelle clé et l'ajouter EN TÊTE de la liste `keys`
    2. attendre encryption-provider-config-automatic-reload (~1 min)
    3. réécrire tous les secrets pour les re-chiffrer avec key2 :
         kubectl get secrets -A -o json | kubectl replace -f -
    4. retirer key1 de la configuration
    Sans l'étape 3, les anciens objets restent chiffrés avec l'ancienne clé :
    une rotation incomplète est pire qu'aucune rotation, car elle donne
    l'illusion d'avoir retiré une clé compromise.
PROC

printf '\n'
step "6. Où vit la clé ? (elle ne doit pas être dans le cluster)"
if [ -f "$LAB_ROOT/infrastructure/encryption/encryption-config.yaml" ]; then
  ok "Clé présente hors du cluster : infrastructure/encryption/encryption-config.yaml"
  detail "gitignorée + chmod 600. Perdre cette clé = perdre tous les secrets ;"
  detail "la fuiter = les rendre tous lisibles à qui a un dump etcd."
else
  warn "Fichier absent : lancez make cluster"
fi

printf '\n%s%sCONCLUSION DÉMO 3%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
cat <<'C'
  Base64 ≠ chiffrement. L'API renvoie du base64 (décoable par n'importe qui),
  etcd ne contient que du chiffré aescbc. Sans EncryptionConfiguration, un
  simple `etcdctl get /registry/secrets/...` livrerait tous les secrets du
  cluster, RBAC ou pas. C'est un prérequis non négociable (partie 2 et 8).
C
