#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Synchronise infrastructure/vault/policy-configmap.yaml depuis le fichier .hcl.
#
# Pourquoi deux sources ? Le .hcl est lisible et commenté (référence humaine),
# la ConfigMap est ce que le Job Kubernetes peut monter. Ce script garantit
# qu'ils ne divergent pas : si le .hcl change, la ConfigMap doit être régénérée.
# ------------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require python3

POLICY="$LAB_ROOT/infrastructure/vault/policies/eso-policy.hcl"
OUT="$LAB_ROOT/infrastructure/vault/policy-configmap.yaml"

python3 - "$POLICY" "$OUT" <<'PY'
import sys
policy_path, out_path = sys.argv[1], sys.argv[2]
body = "\n".join("    " + line if line.strip() else ""
                 for line in open(policy_path).read().splitlines())
header = open(out_path).read()
head = header[:header.index("data:") + len("data:")]
open(out_path, "w").write(head + "\n  eso-policy.hcl: |\n" + body + "\n")
print(f"  politique synchronisée : {policy_path} -> {out_path}")
PY
