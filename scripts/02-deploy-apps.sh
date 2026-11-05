#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Étape 2 — applications, RBAC, NetworkPolicies, Pods de démonstration.
#
# Ordre volontaire :
#   RBAC et ServiceAccounts AVANT les Pods (sinon les Pods démarrent avec
#   l'identité `default` et le moindre privilège n'est jamais appliqué)
#   PostgreSQL AVANT le backend (dépendance réseau)
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

check_cluster
require kubectl docker

title "1. ServiceAccounts et RBAC"
kubectl apply -f "$LAB_ROOT/infrastructure/rbac/serviceaccounts.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/rbac/backend-rbac.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/rbac/database-rbac.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/rbac/frontend-rbac.yaml"
kubectl apply -f "$LAB_ROOT/infrastructure/rbac/dev-user-rbac.yaml"
ok "sa-backend / sa-frontend / sa-database / sa-eso / sa-intrus"

title "2. Image du backend"
if docker image inspect secrets-lab/api-backend:1.0.0 >/dev/null 2>&1; then
  ok "Image déjà construite"
else
  step "docker build (première fois : ~30 s)"
  docker build -t secrets-lab/api-backend:1.0.0 "$LAB_ROOT/apps/backend"
fi
step "Chargement de l'image dans le nœud kind"
kind load docker-image secrets-lab/api-backend:1.0.0 --name "$CLUSTER_NAME"
ok "Image disponible dans le cluster"

title "3. PostgreSQL"
kubectl apply -f "$LAB_ROOT/apps/database/postgres.yaml"
kubectl -n database rollout status statefulset/postgres --timeout=180s
ok "PostgreSQL prêt (mot de passe issu de Vault via ESO)"

title "4. api-backend"
kubectl apply -f "$LAB_ROOT/apps/backend/deployment.yaml"
kubectl -n backend rollout status deploy/api-backend --timeout=180s
ok "Backend prêt"

title "5. Frontend"
kubectl apply -f "$LAB_ROOT/apps/frontend/frontend.yaml"
kubectl -n frontend rollout status deploy/frontend --timeout=180s
ok "Frontend prêt — http://localhost:8080"

title "6. NetworkPolicies (blast radius)"
kubectl apply -f "$LAB_ROOT/infrastructure/policies/network-policies.yaml"
ok "$(kubectl get networkpolicy -A --no-headers | wc -l) politiques appliquées"
warn "Leur APPLICATION dépend du CNI : lancez 'make netpol-check' pour le prouver"

title "7. Pods de démonstration (namespace security)"
kubectl apply -f "$LAB_ROOT/demos/attacker-pod.yaml"
kubectl apply -f "$LAB_ROOT/demos/tools-pod.yaml"
kubectl -n security wait --for=condition=Ready pod/intrus --timeout=120s
kubectl -n security wait --for=condition=Ready pod/tools --timeout=120s
ok "Pods intrus et tools prêts"

title "Vérification fonctionnelle de bout en bout"
step "Le backend se connecte-t-il à PostgreSQL avec le secret synchronisé ?"
kubectl -n backend exec deploy/api-backend -- python -c '
import json, urllib.request
r = json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/db-check", timeout=5))
print(json.dumps(r, indent=2))
' | sed 's/^/    /' || warn "Échec : voir 'make logs-backend'"

step "Le frontend joint-il le backend ?"
curl -s --max-time 5 http://localhost:8080/api/whoami | sed 's/^/    /' \
  || warn "Frontend non joignable : vérifiez 'kubectl -n frontend get pods'"

cat <<'SUMMARY'

Tout est en place. Démonstrations :
  make demo-1-acces-refuse        attaquant sans droit -> Forbidden
  make demo-2-acces-autorise      backend -> lecture nominative OK
  make demo-3-chiffrement-etcd    etcd ne contient que du chiffré
  make demo-4-rotation            rotation sans redémarrage
  make demo-5-networkpolicy       isolation réseau prouvée
  make demo-6-gitleaks            détection de secret dans Git
  make demo-7-utilisateur         utilisateur humain non autorisé
SUMMARY
