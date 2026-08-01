#!/bin/bash
###############################################################
# ZTR DevSecOps - Kubernetes Deployment Script
###############################################################

set -e

NAMESPACE="devsecops"
K8S_DIR="kubernetes"

echo "========================================="
echo " ZTR DevSecOps - Deploying to K8s"
echo "========================================="

echo ""
echo "Checking Kubernetes Cluster..."
kubectl cluster-info

echo ""
echo "--- Applying manifests in order ---"

# Apply namespace first
echo "[1/8] Creating namespace..."
kubectl apply -f ${K8S_DIR}/01-namespace.yaml

# Apply configmaps and secrets
echo "[2/8] Creating configmaps..."
kubectl apply -f ${K8S_DIR}/04-configmap.yaml

echo "[3/8] Creating secrets..."
kubectl apply -f ${K8S_DIR}/05-secret.yaml

# Apply PostgreSQL resources
echo "[4/8] Deploying PostgreSQL..."
kubectl apply -f ${K8S_DIR}/postgres/

# Apply persistent volume
echo "[5/8] Creating PersistentVolume..."
kubectl apply -f ${K8S_DIR}/06-persistent-volume.yaml
echo "Creating PersistentVolumeClaim..."
kubectl apply -f ${K8S_DIR}/07-persistent-volume-claim.yaml

# Deploy nginx
echo "[6/8] Deploying NGINX..."
kubectl apply -f ${K8S_DIR}/nginx/

# Deploy Juice Shop (vulnerable app for scanning)
echo "[7/8] Deploying Juice Shop..."
kubectl apply -f ${K8S_DIR}/juiceshop-deployment.yaml
kubectl apply -f ${K8S_DIR}/juiceshop-service.yaml

# Wait for all deployments
echo "[8/8] Waiting for deployments to roll out..."
kubectl rollout status deployment/postgres -n ${NAMESPACE} --timeout=180s || echo "Postgres rollout timeout (may already be running)"
kubectl rollout status deployment/nginx -n ${NAMESPACE} --timeout=180s || echo "Nginx rollout timeout (may already be running)"
kubectl rollout status deployment/juiceshop -n ${NAMESPACE} --timeout=180s || echo "JuiceShop rollout timeout (may already be running)"

echo ""
echo "========================================="
echo " Deployment Successful!"
echo "========================================="
echo ""
echo "--- Pods ---"
kubectl get pods -n ${NAMESPACE}
echo ""
echo "--- Services ---"
kubectl get svc -n ${NAMESPACE}
echo ""
echo "--- Deployments ---"
kubectl get deployments -n ${NAMESPACE}
