#!/usr/bin/env bash

set -euo pipefail

################################################################################
# Squawk Beta Deployment Script
# Deploys Squawk DNS platform to dal2-beta Kubernetes cluster
# Supports full pipeline: build, push, helm deploy, verify, rollback
################################################################################

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly RELEASE_NAME="squawk"
readonly NAMESPACE="squawk-beta"
readonly CHART_PATH="./k8s/helm/squawk"
readonly IMAGE_REGISTRY="registry-dal2.penguintech.io"
readonly KUBE_CONTEXT="dal2-beta"
readonly APP_HOST="squawk.penguintech.io"
readonly DEFAULT_TAG="beta-$(date +%s)"

# Service definitions (docker build contexts)
declare -A SERVICES=(
  ["dns-server"]="./dns-server"
  ["flask-api"]="./dns-server"
  ["dns-webui"]="./services/dns-webui"
  ["dns-client"]="./dns-client"
)

# Track script parameters
TAG="${DEFAULT_TAG}"
SERVICE=""
SKIP_BUILD=false
DRY_RUN=false
ROLLBACK_RELEASE=false
HELP=false

################################################################################
# Helper Functions
################################################################################

print_header() {
  printf "${BLUE}%s${NC}\n" "$(printf '=%.0s' {1..80})"
  printf "${BLUE}  %s${NC}\n" "$1"
  printf "${BLUE}%s${NC}\n" "$(printf '=%.0s' {1..80})"
}

print_success() {
  printf "${GREEN}✓${NC} %s\n" "$1"
}

print_error() {
  printf "${RED}✗${NC} %s\n" "$1" >&2
}

print_warning() {
  printf "${YELLOW}⚠${NC} %s\n" "$1"
}

print_info() {
  printf "${BLUE}ℹ${NC} %s\n" "$1"
}

print_step() {
  printf "\n${BLUE}→${NC} %s\n" "$1"
}

die() {
  print_error "$1"
  exit 1
}

################################################################################
# Prerequisite Checks
################################################################################

check_prerequisites() {
  print_step "Checking prerequisites"

  # Check required binaries
  local required_bins=("kubectl" "helm" "docker" "kustomize")
  for bin in "${required_bins[@]}"; do
    if ! command -v "$bin" &> /dev/null; then
      die "Required binary not found: $bin"
    fi
  done
  print_success "All required binaries found"

  # Check kubectl context
  local current_context
  current_context=$(kubectl config current-context)
  if [[ "$current_context" != "$KUBE_CONTEXT" ]]; then
    print_warning "Current context: $current_context (expected: $KUBE_CONTEXT)"
    print_info "Switch context with: kubectl config use-context $KUBE_CONTEXT"
  else
    print_success "Kubernetes context: $current_context"
  fi

  # Check helm chart exists
  if [[ ! -f "$CHART_PATH/Chart.yaml" ]]; then
    die "Helm chart not found: $CHART_PATH/Chart.yaml"
  fi
  print_success "Helm chart found: $CHART_PATH"

  # Check Docker daemon
  if ! docker ps &> /dev/null; then
    die "Docker daemon not accessible"
  fi
  print_success "Docker daemon accessible"

  # Check kustomize overlays
  if [[ ! -f "k8s/kustomize/overlays/beta/kustomization.yaml" ]]; then
    die "Kustomize overlay not found: k8s/kustomize/overlays/beta/kustomization.yaml"
  fi
  print_success "Kustomize overlays found"
}

################################################################################
# Docker Build and Push
################################################################################

build_and_push_image() {
  local service_name="$1"
  local build_context="${SERVICES[$service_name]}"
  local image_name="${IMAGE_REGISTRY}/squawk/${service_name}"
  local image_tag="${image_name}:${TAG}"

  print_info "Building: $service_name"
  print_info "Context: $build_context"
  print_info "Image: $image_tag"

  if [[ ! -d "$build_context" ]]; then
    die "Build context not found: $build_context"
  fi

  # Determine Dockerfile based on service
  local dockerfile="Dockerfile"
  if [[ "$service_name" == "flask-api" ]]; then
    dockerfile="Dockerfile.api"
  fi

  # Build image
  if [[ -f "$build_context/$dockerfile" ]]; then
    docker build \
      -f "$build_context/$dockerfile" \
      -t "$image_tag" \
      "$build_context"
    print_success "Built: $image_tag"
  else
    die "Dockerfile not found: $build_context/$dockerfile"
  fi

  # Push image
  print_info "Pushing: $image_tag"
  docker push "$image_tag"
  print_success "Pushed: $image_tag"

  # Tag as beta-latest for consistency
  docker tag "$image_tag" "${image_name}:beta-latest"
  docker push "${image_name}:beta-latest"
  print_success "Tagged and pushed: ${image_name}:beta-latest"
}

build_and_push() {
  print_header "Building and Pushing Images"

  if [[ -n "$SERVICE" ]]; then
    # Build specific service
    if [[ -z "${SERVICES[$SERVICE]:-}" ]]; then
      die "Unknown service: $SERVICE. Available: ${!SERVICES[@]}"
    fi
    build_and_push_image "$SERVICE"
  else
    # Build all services
    for service_name in "${!SERVICES[@]}"; do
      build_and_push_image "$service_name"
    done
  fi
}

################################################################################
# Helm Deployment
################################################################################

deploy_with_helm() {
  print_header "Deploying with Helm"

  local helm_opts=(
    "upgrade"
    "--install"
    "$RELEASE_NAME"
    "$CHART_PATH"
    "--namespace" "$NAMESPACE"
    "--create-namespace"
    "-f" "$CHART_PATH/values-beta.yaml"
    "--set" "image.tag=$TAG"
    "--set" "dnsServer.image.tag=$TAG"
    "--set" "flaskApi.image.tag=$TAG"
    "--set" "dnsWebui.image.tag=$TAG"
    "--set" "dnsClient.image.tag=$TAG"
    "--set" "ingress.hosts[0].host=$APP_HOST"
  )

  # Add dry-run if specified
  if [[ "$DRY_RUN" == true ]]; then
    helm_opts+=("--dry-run" "--debug")
    print_warning "DRY-RUN MODE: No changes will be applied"
  fi

  # Execute helm
  helm "${helm_opts[@]}"

  if [[ "$DRY_RUN" != true ]]; then
    print_success "Helm deployment completed"
  fi
}

################################################################################
# Verification
################################################################################

verify_deployment() {
  print_header "Verifying Deployment"

  local max_attempts=30
  local attempt=0
  local ready_replicas=0

  print_step "Waiting for deployments to be ready (timeout: ${max_attempts}s)"

  while [[ $attempt -lt $max_attempts ]]; do
    # Check deployment status
    ready_replicas=$(kubectl get deployment -n "$NAMESPACE" -o jsonpath='{.items[*].status.readyReplicas}' 2>/dev/null || echo "0")
    total_replicas=$(kubectl get deployment -n "$NAMESPACE" -o jsonpath='{.items[*].spec.replicas}' 2>/dev/null | awk '{s=0; for(i=1;i<=NF;i++) s+=$i} END {print s}')

    printf "  [%d/%d] ready replicas\r" "$ready_replicas" "$total_replicas"

    if [[ "$ready_replicas" -eq "$total_replicas" ]] && [[ "$total_replicas" -gt 0 ]]; then
      printf "\n"
      break
    fi

    ((attempt++))
    sleep 1
  done

  if [[ $attempt -ge $max_attempts ]]; then
    print_warning "Deployment verification timeout (pods may still be starting)"
  else
    print_success "All deployments ready"
  fi

  # Show pod status
  print_step "Pod Status:"
  kubectl get pods -n "$NAMESPACE" -o wide

  # Show service status
  print_step "Service Status:"
  kubectl get svc -n "$NAMESPACE"

  # Show ingress status
  print_step "Ingress Status:"
  kubectl get ingress -n "$NAMESPACE"

  # Health check
  print_step "Health Check Summary:"
  local unhealthy=0
  for pod in $(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'); do
    local status=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
    if [[ "$status" != "Running" ]]; then
      print_warning "Pod $pod is $status"
      ((unhealthy++))
    else
      print_success "Pod $pod is Running"
    fi
  done

  if [[ $unhealthy -eq 0 ]]; then
    print_success "All pods healthy"
  fi

  print_step "Deployment Summary:"
  print_info "Release: $RELEASE_NAME"
  print_info "Namespace: $NAMESPACE"
  print_info "Image Tag: $TAG"
  print_info "App Host: https://$APP_HOST"
  print_info "Kube Context: $KUBE_CONTEXT"
}

################################################################################
# Rollback
################################################################################

rollback() {
  print_header "Rolling Back Deployment"

  print_step "Getting release history"
  helm history "$RELEASE_NAME" -n "$NAMESPACE"

  print_step "Rolling back to previous release"
  if helm rollback "$RELEASE_NAME" -n "$NAMESPACE"; then
    print_success "Rollback completed"
    print_step "Waiting for rollback to complete"
    sleep 10
    verify_deployment
  else
    die "Rollback failed"
  fi
}

################################################################################
# Usage and Help
################################################################################

usage() {
  cat << EOF
${BLUE}Squawk Beta Deployment Script${NC}

Usage: $(basename "$0") [OPTIONS]

OPTIONS:
  --tag TAG               Image tag (default: beta-<epoch>)
  --service SERVICE       Build/deploy specific service
                          Options: dns-server, flask-api, dns-webui, dns-client
  --skip-build            Skip docker build and push phase
  --dry-run               Preview deployment without applying changes
  --rollback              Rollback to previous helm release
  --help                  Show this help message

EXAMPLES:
  # Full deployment with automatic image tag
  $(basename "$0")

  # Deploy with custom tag
  $(basename "$0") --tag beta-v1.2.3

  # Build and deploy only dns-server
  $(basename "$0") --service dns-server

  # Verify deployment without building
  $(basename "$0") --skip-build

  # Preview changes without applying
  $(basename "$0") --dry-run

  # Rollback to previous release
  $(basename "$0") --rollback

CONFIGURATION:
  Release Name:     $RELEASE_NAME
  Namespace:        $NAMESPACE
  Helm Chart:       $CHART_PATH
  Image Registry:   $IMAGE_REGISTRY
  Kube Context:     $KUBE_CONTEXT
  App Host:         https://$APP_HOST

REQUIREMENTS:
  - kubectl configured for $KUBE_CONTEXT context
  - helm 3.x installed
  - docker installed and running
  - kustomize installed
  - Access to $IMAGE_REGISTRY

EOF
}

################################################################################
# Main
################################################################################

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        TAG="$2"
        shift 2
        ;;
      --service)
        SERVICE="$2"
        shift 2
        ;;
      --skip-build)
        SKIP_BUILD=true
        shift
        ;;
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      --rollback)
        ROLLBACK_RELEASE=true
        shift
        ;;
      --help)
        HELP=true
        shift
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if [[ "$HELP" == true ]]; then
    usage
    exit 0
  fi

  print_header "Squawk Beta Deployment"

  # Check prerequisites
  check_prerequisites

  # Handle rollback
  if [[ "$ROLLBACK_RELEASE" == true ]]; then
    rollback
    exit 0
  fi

  # Build and push images
  if [[ "$SKIP_BUILD" != true ]]; then
    build_and_push
  else
    print_step "Skipping build phase (--skip-build)"
  fi

  # Deploy with Helm
  deploy_with_helm

  # Verify if not dry-run
  if [[ "$DRY_RUN" != true ]]; then
    verify_deployment
    print_header "Deployment Successful"
    print_success "Squawk is deployed to https://$APP_HOST"
  else
    print_header "Dry-Run Complete"
    print_info "No changes were applied. Remove --dry-run to deploy."
  fi
}

main "$@"
