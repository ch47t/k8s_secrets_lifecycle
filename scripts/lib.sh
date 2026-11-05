#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Helpers communs à tous les scripts du lab.
# ------------------------------------------------------------------------------
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-secrets-lab}"
LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CLUSTER_NAME LAB_ROOT

if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_DIM=$'\033[2m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""
fi

title()  { printf '\n%s%s══ %s ══%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"; }
step()   { printf '%s→ %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
ok()     { printf '%s✔ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn()   { printf '%s⚠ %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
fail()   { printf '%s✘ %s%s\n' "$C_RED" "$*" "$C_RESET"; }
detail() { printf '%s  %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# Affiche un bloc « commande exécutée »
show_cmd() { printf '%s$ %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

require() {
  for bin in "$@"; do
    command -v "$bin" >/dev/null 2>&1 || { fail "Dépendance manquante : $bin"; exit 1; }
  done
}

# Attend qu'une condition (commande) réussisse. args: description timeout_s commande...
wait_for() {
  local desc="$1" timeout="$2"; shift 2
  local i=0
  while ! "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge "$timeout" ]; then
      fail "Timeout ($timeout s) en attendant : $desc"
      return 1
    fi
    sleep 1
  done
  return 0
}

# Vérifie qu'on est bien dans le cluster du lab
check_cluster() {
  require kubectl
  kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null 2>&1 \
    || { fail "Cluster kind-${CLUSTER_NAME} introuvable. Lancez : make cluster"; exit 1; }
  kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
}
