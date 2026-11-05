# ------------------------------------------------------------------------------
# EncryptionConfiguration — chiffrement au repos des Secrets dans etcd
#
# SANS ce fichier, un Secret Kubernetes n'est qu'un objet JSON en Base64 dans
# etcd : quiconque atteint etcd (sauvegarde, snapshot, accès disque) lit tout
# en clair. Le Base64 n'est PAS du chiffrement (partie 2 du plan).
#
# Provider retenu : aescbc (AES-256-CBC + HMAC) — recommandé par la doc
# Kubernetes, disponible partout, plus simple à expliquer que secretbox.
#
# __AESCBC_KEY__ est remplacé par une clé aléatoire de 32 octets encodée en
# base64, générée par scripts/00-create-cluster.sh. La clé NE DOIT JAMAIS être
# committée : c'est elle qui protège tous les secrets du cluster.
#
# Rotation de clé (documentée partie 4) :
#   1. ajouter une nouvelle entrée EN TÊTE de la liste `keys`
#   2. attendre le rechargement automatique de l'API server (~1 min)
#   3. réécrire tous les secrets :  kubectl get secrets -A -o json | kubectl replace -f -
#   4. supprimer l'ancienne clé de la liste
# ------------------------------------------------------------------------------
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps          # recommandé : on y met parfois de la config sensible
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: __AESCBC_KEY__
      - identity: {}        # lecture des objets encore non chiffrés (migration)
