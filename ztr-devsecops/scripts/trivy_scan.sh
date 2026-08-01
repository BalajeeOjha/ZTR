#!/bin/bash
###############################################################
# ZTR DevSecOps - Trivy Security Scanner
# Scans all container images deployed in the cluster
###############################################################

set -e

REPORT_DIR="reports"
mkdir -p ${REPORT_DIR}

echo "========================================="
echo " ZTR - Trivy Security Scanner"
echo "========================================="

# Create combined JSON report
echo "[1/3] Scanning Juice Shop image (primary target)..."
trivy image \
    --format json \
    --output ${REPORT_DIR}/trivy-image-report.json \
    bkimminich/juice-shop:latest 2>/dev/null || true

echo "[2/3] Scanning NGINX image..."
trivy image \
    --format json \
    --output ${REPORT_DIR}/trivy-nginx-report.json \
    nginx:latest 2>/dev/null || true

echo "[3/3] Scanning PostgreSQL image..."
trivy image \
    --format json \
    --output ${REPORT_DIR}/trivy-postgres-report.json \
    postgres:16 2>/dev/null || true

# Also generate human-readable table reports
echo ""
echo "--- Generating human-readable reports ---"

trivy image --severity CRITICAL,HIGH --format table \
    bkimminich/juice-shop:latest 2>/dev/null > ${REPORT_DIR}/trivy-juiceshop-critical.txt || true

echo ""
echo "========================================="
echo " Scans Complete!"
echo " Reports saved to ${REPORT_DIR}/"
echo "========================================="
