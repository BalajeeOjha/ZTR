#!/bin/bash
set -e

echo "========================================"
echo " ZTR DevSecOps - VM Bootstrap"
echo "========================================"

echo "[1/8] Updating Ubuntu..."
sudo apt update
sudo apt upgrade -y

echo "[2/8] Installing required packages..."
sudo apt install -y \
    curl wget git unzip \
    apt-transport-https \
    ca-certificates gnupg \
    lsb-release software-properties-common

echo "[3/8] Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker vagrant
sudo systemctl enable docker
sudo systemctl start docker

echo "[4/8] Installing kubectl..."
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

echo "[5/8] Installing Minikube..."
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
chmod +x minikube-linux-amd64
sudo mv minikube-linux-amd64 /usr/local/bin/minikube

echo "[6/8] Installing Helm..."
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

echo "[7/8] Installing Trivy..."
sudo wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
sudo echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(. /etc/os-release && echo $VERSION_CODENAME) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install -y trivy

echo "[8/8] Starting Minikube cluster..."
sudo -u vagrant minikube start --driver=docker --memory=4096 --cpus=2

# Wait for cluster to be ready
echo "Waiting for Minikube to be ready..."
sudo -u vagrant minikube status

echo ""
echo "========================================"
echo " Tool Versions"
echo "========================================"
docker --version
docker compose version
kubectl version --client --short 2>/dev/null || kubectl version --client
minikube version
helm version --short 2>/dev/null || helm version
trivy --version

echo ""
echo "========================================"
echo " Bootstrap Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  cd /vagrant && docker compose up -d --build"
echo "  Then open: http://192.168.56.10:8080 (Jenkins)"
echo ""
