# ------------------------------------------------------------------------------
# Politique Vault du seul client non humain : External Secrets Operator.
#
# Principe : ESO lit, ne modifie jamais. Aucun accès à sys/*, à auth/*, aux
# clés de scellement, ni aux autres chemins du KV. Si le Pod ESO est compromis,
# l'attaquant récupère uniquement les secrets que ESO est censé synchroniser,
# et il ne peut ni créer de politiques, ni élargir ses droits.
# ------------------------------------------------------------------------------

# 1. KV v2 — lecture seule des secrets applicatifs du projet
path "secret/data/backend/*" {
  capabilities = ["read"]
}
path "secret/data/database/*" {
  capabilities = ["read"]
}
# lecture des métadonnées = indispensable pour détecter une nouvelle version
path "secret/metadata/backend/*" {
  capabilities = ["read"]
}
path "secret/metadata/database/*" {
  capabilities = ["read"]
}

# 2. Dynamic secrets PostgreSQL — génération de credentials à TTL court
path "database/creds/app" {
  capabilities = ["read"]
}

# 3. Interdictions explicites (documentées pour l'audit)
#    deny l'emporte toujours sur allow, même si un autre chemin matche.
path "secret/data/prod-*" {
  capabilities = ["deny"]
}
path "sys/*" {
  capabilities = ["deny"]
}
path "auth/token/*" {
  capabilities = ["deny"]
}
path "identity/*" {
  capabilities = ["deny"]
}
