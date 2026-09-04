#!/bin/bash
# Squawk DNS Kubernetes Installation Script
# This script provides options for installing Squawk DNS using kubectl or Helm

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-squawk-dns}"
RELEASE_NAME="${RELEASE_NAME:-squawk}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo " Squawk DNS - Kubernetes Installation"
    echo "=============================================="
    echo -e "${NC}"
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  kubectl           Install using kubectl and kustomize"
    echo "  helm              Install using Helm v3"
    echo "  uninstall         Uninstall Squawk DNS"
    echo "  status            Check installation status"
    echo ""
    echo "Options:"
    echo "  -n, --namespace   Kubernetes namespace (default: squawk-dns)"
    echo "  -e, --env         Environment: development, production (default: base)"
    echo "  -f, --values      Helm values file (for helm command)"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 kubectl                           # Install with kubectl (base)"
    echo "  $0 kubectl -e production             # Install production overlay"
    echo "  $0 helm                              # Install with Helm defaults"
    echo "  $0 helm -f custom-values.yaml        # Install with custom values"
    echo "  $0 uninstall                         # Uninstall"
}

check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}Error: kubectl is not installed${NC}"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
        exit 1
    fi

    echo -e "${GREEN}Prerequisites check passed${NC}"
}

install_kubectl() {
    local env="${1:-base}"

    echo -e "${YELLOW}Installing Squawk DNS using kubectl (environment: $env)...${NC}"

    if [ "$env" = "base" ]; then
        kubectl apply -k "${SCRIPT_DIR}/manifests/"
    else
        if [ ! -d "${SCRIPT_DIR}/manifests/overlays/${env}" ]; then
            echo -e "${RED}Error: Environment overlay '${env}' not found${NC}"
            exit 1
        fi
        kubectl apply -k "${SCRIPT_DIR}/manifests/overlays/${env}/"
    fi

    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "To check status:"
    echo "  kubectl get pods -n ${NAMESPACE}"
    echo ""
    echo "To access the web console:"
    echo "  kubectl port-forward -n ${NAMESPACE} svc/squawk-frontend 3000:3000"
}

install_helm() {
    local values_file="$1"

    if ! command -v helm &> /dev/null; then
        echo -e "${RED}Error: helm is not installed${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Installing Squawk DNS using Helm...${NC}"

    # Update dependencies
    echo "Updating Helm dependencies..."
    helm dependency update "${SCRIPT_DIR}/helm/squawk/"

    # Install or upgrade
    local helm_args=(
        upgrade --install "${RELEASE_NAME}"
        "${SCRIPT_DIR}/helm/squawk/"
        --namespace "${NAMESPACE}"
        --create-namespace
    )

    if [ -n "$values_file" ]; then
        helm_args+=(-f "$values_file")
    fi

    helm "${helm_args[@]}"

    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "To check status:"
    echo "  helm status ${RELEASE_NAME} -n ${NAMESPACE}"
    echo "  kubectl get pods -n ${NAMESPACE}"
}

uninstall() {
    echo -e "${YELLOW}Uninstalling Squawk DNS...${NC}"

    # Try Helm first
    if command -v helm &> /dev/null; then
        if helm status "${RELEASE_NAME}" -n "${NAMESPACE}" &> /dev/null; then
            echo "Uninstalling Helm release..."
            helm uninstall "${RELEASE_NAME}" -n "${NAMESPACE}"
        fi
    fi

    # Delete kubectl resources
    echo "Deleting kubectl resources..."
    kubectl delete -k "${SCRIPT_DIR}/manifests/" --ignore-not-found || true

    # Delete namespace
    read -p "Delete namespace ${NAMESPACE}? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete namespace "${NAMESPACE}" --ignore-not-found
    fi

    echo -e "${GREEN}Uninstall complete!${NC}"
}

status() {
    echo -e "${YELLOW}Checking Squawk DNS status...${NC}"
    echo ""

    echo "=== Pods ==="
    kubectl get pods -n "${NAMESPACE}" -o wide 2>/dev/null || echo "No pods found"
    echo ""

    echo "=== Services ==="
    kubectl get svc -n "${NAMESPACE}" 2>/dev/null || echo "No services found"
    echo ""

    echo "=== DaemonSet (DNS Agent) ==="
    kubectl get daemonset -n "${NAMESPACE}" 2>/dev/null || echo "No DaemonSet found"
    echo ""

    if command -v helm &> /dev/null; then
        echo "=== Helm Release ==="
        helm status "${RELEASE_NAME}" -n "${NAMESPACE}" 2>/dev/null || echo "No Helm release found"
    fi
}

# Parse arguments
COMMAND=""
ENV="base"
VALUES_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        kubectl|helm|uninstall|status)
            COMMAND="$1"
            shift
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -e|--env)
            ENV="$2"
            shift 2
            ;;
        -f|--values)
            VALUES_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Main
print_header

if [ -z "$COMMAND" ]; then
    print_usage
    exit 1
fi

check_prerequisites

case $COMMAND in
    kubectl)
        install_kubectl "$ENV"
        ;;
    helm)
        install_helm "$VALUES_FILE"
        ;;
    uninstall)
        uninstall
        ;;
    status)
        status
        ;;
esac
