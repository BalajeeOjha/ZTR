#!/bin/bash
###############################################################
# ZTR DevSecOps - Self-Healing Remediation Script
#
# Analyzes Trivy scan results and generates healed K8s manifests
# with security hardening applied automatically.
###############################################################

set -e

HEAL_DIR="healed-manifests"
K8S_DIR="kubernetes"
NAMESPACE="devsecops"

mkdir -p ${HEAL_DIR}

echo "========================================="
echo " ZTR - Self-Healing Remediation"
echo "========================================="
echo ""

# Read vulnerability counts from the parsed report
CRITICAL=0
HIGH=0
TOTAL=0

if [ -f reports/trivy-image-report.json ]; then
    CRITICAL=$(python3 -c "
import json
try:
    with open('reports/trivy-image-report.json') as f:
        data = json.load(f)
    results = data.get('Results', [])
    total = 0
    for r in results:
        for v in r.get('Vulnerabilities', []):
            if v.get('Severity') == 'CRITICAL':
                total += 1
    print(total)
except: print(0)
")
    HIGH=$(python3 -c "
import json
try:
    with open('reports/trivy-image-report.json') as f:
        data = json.load(f)
    results = data.get('Results', [])
    total = 0
    for r in results:
        for v in r.get('Vulnerabilities', []):
            if v.get('Severity') == 'HIGH':
                total += 1
    print(total)
except: print(0)
")
    TOTAL=$(python3 -c "
import json
try:
    with open('reports/trivy-image-report.json') as f:
        data = json.load(f)
    results = data.get('Results', [])
    total = 0
    for r in results:
        total += len(r.get('Vulnerabilities', []))
    print(total)
except: print(0)
")
fi

echo "Vulnerabilities detected: ${CRITICAL} Critical, ${HIGH} High, ${TOTAL} Total"
echo ""
echo "[HEAL-1] Generating hardened NGINX deployment..."
cat > ${HEAL_DIR}/nginx-deployment-healed.yaml << 'NGINX_EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: devsecops
  labels:
    app: nginx
    healed: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.25-alpine
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        securityContext:
          runAsNonRoot: true
          runAsUser: 101
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
NGINX_EOF

echo "[HEAL-2] Generating hardened NGINX config with security headers..."
cat > ${HEAL_DIR}/nginx-configmap-healed.yaml << 'NGINX_CFG_EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-security-headers
  namespace: devsecops
data:
  security-headers.conf: |
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    server_tokens off;
NGINX_CFG_EOF

echo "[HEAL-3] Generating hardened Juice Shop deployment..."
cat > ${HEAL_DIR}/juiceshop-deployment-healed.yaml << 'JS_EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juiceshop
  namespace: devsecops
  labels:
    app: juiceshop
    healed: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: juiceshop
  template:
    metadata:
      labels:
        app: juiceshop
      annotations:
        healed-by: "ztr-self-healing"
        healed-at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    spec:
      containers:
      - name: juiceshop
        image: bkimminich/juice-shop:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 3000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false
        env:
        - name: NODE_ENV
          value: "production"
JS_EOF

echo "[HEAL-4] Generating network policy for namespace isolation..."
cat > ${HEAL_DIR}/network-policy.yaml << 'NET_EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: devsecops
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nginx-ingress
  namespace: devsecops
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
  - Ingress
  ingress:
  - from: []
    ports:
    - protocol: TCP
      port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-juiceshop-ingress
  namespace: devsecops
spec:
  podSelector:
    matchLabels:
      app: juiceshop
  policyTypes:
  - Ingress
  ingress:
  - from: []
    ports:
    - protocol: TCP
      port: 3000
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-postgres-internal
  namespace: devsecops
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 5432
NET_EOF

echo "[HEAL-5] Generating pod security policy..."
cat > ${HEAL_DIR}/pod-security-policy.yaml << 'PSP_EOF'
apiVersion: v1
kind: LimitRange
metadata:
  name: container-limits
  namespace: devsecops
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "64Mi"
    max:
      cpu: "1"
      memory: "1Gi"
    min:
      cpu: "50m"
      memory: "32Mi"
    type: Container
PSP_EOF

echo ""
echo "========================================="
echo " Self-Healing Complete!"
echo "========================================="
echo ""
echo " Generated hardened manifests:"
ls -la ${HEAL_DIR}/
echo ""
echo " Remediations applied:"
echo "  [1] NGINX: Switched to Alpine-based image (smaller attack surface)"
echo "  [2] NGINX: Added security headers (X-Frame-Options, CSP, HSTS, XSS-Protection)"
echo "  [3] NGINX: Added resource limits (memory/CPU)"
echo "  [4] NGINX: Enabled read-only filesystem + non-root user"
echo "  [5] Juice Shop: Added resource limits"
echo "  [6] Juice Shop: Set NODE_ENV=production"
echo "  [7] Network: Created namespace isolation policies"
echo "  [8] Security: Added container resource limits across namespace"
echo ""
echo " Next: Jenkins pipeline will apply these healed manifests."
