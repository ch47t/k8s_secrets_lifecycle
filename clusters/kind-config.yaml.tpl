# ------------------------------------------------------------------------------
# Cluster kind du lab — Mini-projet 6 : cycle de vie des secrets
#
# Ce qui est spécifique ici :
#   1. EncryptionConfiguration montée dans le nœud puis passée à kube-apiserver
#      -> chiffrement au repos des Secrets dans etcd (aescbc)
#   2. automatic-reload : la clé peut être tournée sans redémarrer l'API server
#   3. Audit policy + audit log : trace de QUI lit QUEL secret (partie 4 et 6)
#   4. Port 80 du nœud mappé sur 8080 de l'hôte pour exposer le frontend
#
# __LAB_ROOT__ est remplacé par scripts/00-create-cluster.sh car kind exige
# des chemins absolus dans extraMounts.
# ------------------------------------------------------------------------------
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: secrets-lab
nodes:
  - role: control-plane
    extraPortMappings:
      # NodePort 30080 du Service "frontend" -> http://localhost:8080
      - containerPort: 30080
        hostPort: 8080
        protocol: TCP
    extraMounts:
      - hostPath: __LAB_ROOT__/infrastructure/encryption/encryption-config.yaml
        containerPath: /etc/kubernetes/encryption/encryption-config.yaml
        readOnly: true
      - hostPath: __LAB_ROOT__/infrastructure/encryption/audit-policy.yaml
        containerPath: /etc/kubernetes/audit-policy.yaml
        readOnly: true
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            encryption-provider-config: /etc/kubernetes/encryption-config.yaml
            encryption-provider-config-automatic-reload: "true"
            audit-policy-file: /etc/kubernetes/audit-policy.yaml
            audit-log-path: /var/log/kubernetes/audit.log
            audit-log-maxage: "7"
            audit-log-maxbackup: "3"
            audit-log-maxsize: "100"
          extraVolumes:
            - name: encryption-config
              hostPath: /etc/kubernetes/encryption-config.yaml
              mountPath: /etc/kubernetes/encryption-config.yaml
              readOnly: true
              pathType: File
            - name: audit-policy
              hostPath: /etc/kubernetes/audit-policy.yaml
              mountPath: /etc/kubernetes/audit-policy.yaml
              readOnly: true
              pathType: File
            - name: audit-log
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              pathType: DirectoryOrCreate
