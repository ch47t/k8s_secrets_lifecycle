# ==============================================================================
# Mini-projet 6 — Sécurisation du cycle de vie des secrets dans Kubernetes
#
#   make cluster        crée le cluster kind avec chiffrement etcd + audit
#   make vault-eso      Vault, auth Kubernetes, ESO, synchronisation
#   make apps           RBAC, PostgreSQL, backend, frontend, NetworkPolicies
#   make up             les trois d'étapes ci-dessus, dans l'ordre
#   make demo-N-...     les 7 démonstrations du dossier
#   make teardown       détruit tout
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

CLUSTER_NAME ?= secrets-lab
export CLUSTER_NAME

.PHONY: help cluster vault-eso apps up down teardown status validate \
        demo-1-acces-refuse demo-2-acces-autorise demo-3-chiffrement-etcd \
        demo-4-rotation demo-5-networkpolicy demo-6-gitleaks demo-7-utilisateur \
        demos netpol-check install-calico logs-backend rotation-status \
        policy-configmap hooks rapport

help: ## Affiche cette aide
	@echo ""
	@echo "  Mini-projet 6 — Cycle de vie des secrets dans Kubernetes"
	@echo "  ─────────────────────────────────────────────────────────"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-26s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Prérequis : docker, kind, kubectl, helm, openssl"
	@echo "  Optionnel : gitleaks (démo 6), kubeconform (validation)"
	@echo ""

# ─────────────────────────────────────────────────────────────── infrastructure
cluster: ## Crée le cluster kind (chiffrement etcd aescbc + audit log)
	@bash scripts/00-create-cluster.sh

vault-eso: ## Déploie Vault, le bootstrap (auth K8s, database) et ESO
	@bash scripts/01-deploy-vault-eso.sh

apps: ## Déploie RBAC, PostgreSQL, backend, frontend, NetworkPolicies
	@bash scripts/02-deploy-apps.sh

up: cluster vault-eso apps ## Déploiement complet
	@echo ""
	@echo "  ✔ Plateforme complète — frontend : http://localhost:8080"

down: ## Supprime le cluster (garde les fichiers générés)
	@kind delete cluster --name $(CLUSTER_NAME)

teardown: ## Détruit le cluster ET les fichiers générés (clé etcd incluse)
	@bash scripts/99-teardown.sh

install-calico: ## Recrée le cluster avec Calico (NetworkPolicy réellement appliquées)
	@bash scripts/install-calico.sh

# ──────────────────────────────────────────────────────────────── démonstrations
demo-1-acces-refuse: ## DÉMO 1 — Pod non autorisé -> Forbidden
	@bash scripts/10-demo-1-acces-refuse.sh

demo-2-acces-autorise: ## DÉMO 2 — Backend : lecture nominative + volume monté
	@bash scripts/11-demo-2-acces-autorise.sh

demo-3-chiffrement-etcd: ## DÉMO 3 — etcd ne contient que du chiffré
	@bash scripts/12-demo-3-chiffrement-etcd.sh

demo-4-rotation: ## DÉMO 4 — Rotation sans redémarrage (Vault -> ESO -> volume)
	@bash scripts/13-demo-4-rotation.sh

demo-5-networkpolicy: ## DÉMO 5 — Isolation réseau et blast radius
	@bash scripts/14-demo-5-networkpolicy.sh

demo-6-gitleaks: ## DÉMO 6 — Détection de secrets dans Git
	@bash scripts/15-demo-6-gitleaks.sh

demo-7-utilisateur: ## DÉMO 7 — Utilisateur humain non autorisé (certificat)
	@bash scripts/16-demo-7-utilisateur.sh

demos: demo-1-acces-refuse demo-2-acces-autorise demo-3-chiffrement-etcd \
       demo-4-rotation demo-5-networkpolicy demo-6-gitleaks demo-7-utilisateur ## Toutes les démos

# ───────────────────────────────────────────────────────────────────── contrôles
rapport: ## Régénère docs/RAPPORT.md à partir des documents de docs/
	@bash scripts/95-build-rapport.sh

validate: ## Validation statique (YAML, kubeconform, anti-patterns)
	@bash scripts/90-validate.sh

netpol-check: ## Prouve que les NetworkPolicy sont appliquées (contrôle + négatif)
	@bash scripts/91-netpol-check.sh

policy-configmap: ## Régénère la ConfigMap de politique Vault depuis le fichier .hcl
	@bash scripts/generate-policy-configmap.sh

hooks: ## Installe le hook pre-commit gitleaks
	@command -v pre-commit >/dev/null && pre-commit install || \
	  echo "pre-commit non installé : pip install pre-commit && make hooks"

# ───────────────────────────────────────────────────────────────────── diagnostic
status: ## État complet du lab en une vue
	@echo ""
	@echo "── Cluster ──"; kind get clusters || true
	@echo ""; echo "── Pods ──"; kubectl get pods -A -o wide 2>/dev/null | grep -vE 'kube-system|kube-public|kube-node' || true
	@echo ""; echo "── ExternalSecrets ──"; kubectl get externalsecret -A 2>/dev/null || true
	@echo ""; echo "── Secrets (noms seulement) ──"; kubectl get secrets -n backend -n database 2>/dev/null || true
	@echo ""; echo "── Frontend ──"; curl -s --max-time 3 http://localhost:8080/ >/dev/null && echo "  http://localhost:8080 OK" || echo "  frontend non joignable"

logs-backend: ## Logs de l'API backend (sans secret : les logs ne contiennent que des empreintes)
	@kubectl -n backend logs deploy/api-backend --tail=50

rotation-status: ## Inspecte l'état de synchronisation ESO
	@kubectl -n backend get externalsecret db-credentials -o yaml | sed -n '/status:/,$$p'
	@echo ""
	@kubectl -n backend get secret db-credentials -o jsonpath='{.data.password}' | base64 -d | sha256sum | cut -c1-12 | sed 's/^/empreinte Secret K8s : /'
