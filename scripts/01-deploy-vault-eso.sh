#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Étape 1 — Vault, bootstrap, External Secrets Operator, synchronisation.
#
# Point d'honnêteté : ce script GÉNÈRE les secrets initiaux (mot de passe
# PostgreSQL, clé JWT, clé API partenaire) avec openssl, puis les injecte dans
# un Secret Kubernetes éphémère consommé par le Job de bootstrap. Ils ne
# transitent donc JAMAIS par Git, et le dépôt ne contient aucun credential.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

check_cluster
require kubectl openssl
command -v helm >/dev/null 2>&1 || { fail "helm requis : https://helm.sh/docs/intro/install/"; exit 1; }

title "1. Namespaces"
kubectl apply -f "$LAB_ROOT/infrastructure/namespaces/namespaces.yaml"
ok "frontend / backend / database / vault / external-secrets / security"

title "2. Paramètres de bootstrap (générés hors Git)"
if kubectl -n vault get secret vault-bootstrap-params >/dev/null 2>&1; then
  warn "Secret vault-bootstrap-params existant : conservé (pas de réécriture de mot de passe)"
else
  PG_APP_USER="app"
  PG_APP_PASSWORD="$(openssl rand -hex 24)"
  JWT_SIGNING_KEY="$(openssl rand -base64 48 | tr -d '\n')"
  EXTERNAL_API_KEY="sk_lab_$(openssl rand -hex 16)"

  kubectl create secret generic vault-bootstrap-params -n vault \
    --from-literal=VAULT_ROOT_TOKEN=root \
    --from-literal=PG_APP_USER="$PG_APP_USER" \
    --from-literal=PG_APP_PASSWORD="$PG_APP_PASSWORD" \
    --from-literal=JWT_SIGNING_KEY="$JWT_SIGNING_KEY" \
    --from-literal=EXTERNAL_API_KEY="$EXTERNAL_API_KEY" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  ok "Identifiants initiaux générés (24 octets d'entropie) et stockés dans vault/"
  detail "Empreinte du mot de passe PostgreSQL : $(printf %s "$PG_APP_PASSWORD" | sha256sum | cut -c1-12)"
fi

title "3. Vault + RBAC d'authentification + ConfigMaps"
kubectl apply -f "$LAB_ROOT/infrastructure/vault/vault-auth-rbac.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/vault/vault-dev.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/vault/policy-configmap.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/vault/bootstrap-script-configmap.yaml"
kubectl -n vault rollout status deploy/vault --timeout=180s
ok "Vault démarré (mode dev : mémoire, scellé automatiquement)"

title "4. Bootstrap de Vault (auth K8s, moteur database, seed KV, politique)"
kubectl -n vault delete job vault-bootstrap --ignore-not-found >/dev/null
kubectl apply -f "$LAB_ROOT/infrastructure/vault/bootstrap-job.yaml"
if ! kubectl -n vault wait --for=condition=complete job/vault-bootstrap --timeout=240s; then
  fail "Le bootstrap a échoué. Logs :"
  kubectl -n vault logs job/vault-bootstrap --tail=50 || true
  exit 1
fi
kubectl -n vault logs job/vault-bootstrap --tail=15 | sed 's/^/    /'
ok "Vault configuré : auth/kubernetes, database/, secret/, politique eso-policy"

title "5. External Secrets Operator"
if helm -n external-secrets status external-secrets >/dev/null 2>&1; then
  warn "ESO déjà installé"
else
  helm repo add external-secrets https://charts.external-secrets.io >/dev/null
  helm repo update >/dev/null
  helm install external-secrets external-secrets/external-secrets \
    -n external-secrets \
    --set installCRDs=true \
    --wait --timeout 300s
fi
kubectl -n external-secrets rollout status deploy/external-secrets --timeout=180s
ok "ESO opérationnel"

title "6. ClusterSecretStore + ExternalSecrets"
kubectl apply -f "$LAB_ROOT/infrastructure/eso/cluster-secret-store.yaml"

step "Attente que le store soit Valid"
if wait_for "ClusterSecretStore Valid" 90 \
   bash -c "kubectl get clustersecretstore vault-backend -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"; then
  ok "ClusterSecretStore vault-backend : Ready"
else
  warn "Store non Ready — diagnostic :"
  kubectl get clustersecretstore vault-backend -o yaml | sed -n '/status:/,$p' | head -30
  detail "Cause fréquente : impossible de projeter le JWT (audiences) ou Vault injoignable"
fi

kubectl apply -f "$LAB_ROOT/infrastructure/eso/externalsecrets.yaml"

step "Attente de la synchronisation des Secrets Kubernetes"
for ns_secret in "backend:db-credentials" "backend:jwt-key" "backend:external-api-key" "database:db-credentials"; do
  ns="${ns_secret%%:*}"; sec="${ns_secret##*:}"
  if wait_for "Secret $ns/$sec" 120 kubectl -n "$ns" get secret "$sec"; then
    ok "Secret créé par ESO : $ns/$sec"
  else
    fail "Secret $ns/$sec non créé. Diagnostic :"
    kubectl -n "$ns" get externalsecret
    kubectl -n "$ns" describe externalsecret "$sec" | tail -20
    exit 1
  fi
done

title "État de la synchronisation"
kubectl get externalsecret -A
printf '\n'
kubectl get secret -n backend -n database 2>/dev/null || true

cat <<'SUMMARY'

Chaîne de confiance en place :
  Vault (source de vérité)
    └─ auth Kubernetes (JWT du ServiceAccount sa-eso, validé par TokenReview)
        └─ ESO (refreshInterval: 30s)
            └─ Secrets Kubernetes backend/database
                └─ volumes montés dans les Pods

Étape suivante : make apps
SUMMARY
