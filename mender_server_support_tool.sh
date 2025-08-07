#!/bin/bash

set -euo pipefail

# Global variables
TMP_DIR=""
NAMESPACE=""
HELM_RELEASE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SUPPORT_BUNDLE="mender_support_${TIMESTAMP}.tar.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
  local exit_code=$?
  echo -e "\n${YELLOW}Cleaning up...${NC}"
  if [[ -n "$TMP_DIR" ]] && [[ -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
    echo -e "${GREEN}Temporary directory cleaned up${NC}"
  fi
  exit $exit_code
}

# Set trap for cleanup on script exit
trap cleanup EXIT INT TERM

# Function to print colored messages
print_msg() {
  local color=$1
  local msg=$2
  echo -e "${color}${msg}${NC}"
}

# Function to check if a command exists
check_command() {
  local cmd=$1
  if ! command -v "$cmd" &>/dev/null; then
    print_msg "$RED" "Error: $cmd is not installed or not in PATH"
    return 1
  else
    print_msg "$GREEN" "✓ $cmd is installed"
    return 0
  fi
}

# Function to check all required tools
check_requirements() {
  print_msg "$YELLOW" "Checking required tools..."
  local all_good=true

  for tool in helm kubectl jq; do
    if ! check_command "$tool"; then
      all_good=false
    fi
  done

  if [[ "$all_good" == false ]]; then
    print_msg "$RED" "Please install missing tools before running this script"
    exit 1
  fi

  echo ""
}

# Function to select namespace
select_namespace() {
  print_msg "$YELLOW" "Fetching available namespaces..."

  # Get namespaces and store in array
  mapfile -t namespaces < <(kubectl get ns -o json | jq -r '.items[].metadata.name' | sort)

  if [[ ${#namespaces[@]} -eq 0 ]]; then
    print_msg "$RED" "No namespaces found"
    exit 1
  fi

  print_msg "$GREEN" "Available namespaces:"
  for i in "${!namespaces[@]}"; do
    printf "%3d) %s\n" $((i + 1)) "${namespaces[$i]}"
  done

  while true; do
    read -p "Select the namespace where Mender is instralled (1-${#namespaces[@]}): " selection
    if [[ "$selection" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#namespaces[@]})); then
      NAMESPACE="${namespaces[$((selection - 1))]}"
      print_msg "$GREEN" "Selected namespace: $NAMESPACE"
      echo ""
      break
    else
      print_msg "$RED" "Invalid selection. Please try again."
    fi
  done
}

# Function to select helm release
select_helm_release() {
  print_msg "$YELLOW" "Fetching Helm releases in namespace '$NAMESPACE'..."

  # Get helm releases in the selected namespace
  mapfile -t releases < <(helm ls -n "$NAMESPACE" -o json | jq -r '.[].name' | sort)

  if [[ ${#releases[@]} -eq 0 ]]; then
    print_msg "$RED" "No Helm releases found in namespace '$NAMESPACE'"
    exit 1
  fi

  # Check if 'mender' exists in the releases
  local default_selection=""
  for i in "${!releases[@]}"; do
    if [[ "${releases[$i]}" == "mender" ]]; then
      default_selection=$((i + 1))
      break
    fi
  done

  print_msg "$GREEN" "Available Helm releases:"
  for i in "${!releases[@]}"; do
    if [[ "${releases[$i]}" == "mender" ]]; then
      printf "%3d) %s (default)\n" $((i + 1)) "${releases[$i]}"
    else
      printf "%3d) %s\n" $((i + 1)) "${releases[$i]}"
    fi
  done

  while true; do
    if [[ -n "$default_selection" ]]; then
      read -p "Select Helm release (1-${#releases[@]}) [default: $default_selection]: " selection
      selection=${selection:-$default_selection}
    else
      read -p "Select Helm release (1-${#releases[@]}): " selection
    fi

    if [[ "$selection" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#releases[@]})); then
      HELM_RELEASE="${releases[$((selection - 1))]}"
      print_msg "$GREEN" "Selected Helm release: $HELM_RELEASE"
      echo ""
      break
    else
      print_msg "$RED" "Invalid selection. Please try again."
    fi
  done
}

# Function to create temporary directory
create_tmp_dir() {
  print_msg "$YELLOW" "Creating temporary directory..."
  TMP_DIR=$(mktemp -d -t mender-support-XXXXXX)
  print_msg "$GREEN" "Temporary directory created: $TMP_DIR"
  echo ""
}

# Function to collect helm history
collect_helm_history() {
  local output_file="$TMP_DIR/helm_history.txt"
  print_msg "$YELLOW" "Collecting Helm history for release '$HELM_RELEASE'..."

  {
    echo "Helm History for release: $HELM_RELEASE"
    echo "Namespace: $NAMESPACE"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
  } >"$output_file"

  if helm history "$HELM_RELEASE" -n "$NAMESPACE" >>"$output_file" 2>&1; then
    print_msg "$GREEN" "✓ Helm history saved to $(basename "$output_file")"
  else
    print_msg "$YELLOW" "⚠ Error collecting helm history, see $(basename "$output_file") for details"
  fi
}

# Function to collect helm list output
collect_helm_list() {
  local output_file="$TMP_DIR/helm_list.txt"
  print_msg "$YELLOW" "Collecting Helm list output..."

  {
    echo "Helm List Output"
    echo "Namespace: $NAMESPACE"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
  } >"$output_file"

  if helm ls -n "$NAMESPACE" -a >>"$output_file" 2>&1; then
    print_msg "$GREEN" "✓ Helm list saved to $(basename "$output_file")"
  else
    print_msg "$YELLOW" "⚠ Error collecting helm list, see $(basename "$output_file") for details"
  fi
}

# Function to mask secrets in values
mask_secrets() {
  # Read from stdin and mask common secret patterns
  sed -E \
    -e 's/(password["\s]*:["\s]*)[^"\s,}]+/\1*****************/gi' \
    -e 's/(secret["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(token["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(key["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(apikey["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(credential["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(access_key["\s]*:["\s]*)[^"\s,}]+/\1****************/gi' \
    -e 's/(private[_-]?key["\s]*:["\s]*)[^"\s,}]+/\1****************/gi'
}

# Function to collect helm values
collect_helm_values() {
  local output_file="$TMP_DIR/helm_values.yaml"
  print_msg "$YELLOW" "Collecting Helm values for release '$HELM_RELEASE' (secrets will be masked)..."

  # First, get the values into a temporary variable to avoid pipe failures
  local values_output
  if values_output=$(helm get values "$HELM_RELEASE" -n "$NAMESPACE" --all 2>&1); then
    {
      echo "# Helm Values for release: $HELM_RELEASE"
      echo "# Namespace: $NAMESPACE"
      echo "# Timestamp: $(date)"
      echo "# Note: Sensitive values have been masked with ***********"
      echo "# ----------------------------------------"
      echo "$values_output" | mask_secrets
    } >"$output_file"
    print_msg "$GREEN" "✓ Helm values saved to $(basename "$output_file")"
  else
    {
      echo "# Helm Values for release: $HELM_RELEASE"
      echo "# Namespace: $NAMESPACE"
      echo "# Timestamp: $(date)"
      echo "# ----------------------------------------"
      echo "Error collecting helm values:"
      echo "$values_output"
    } >"$output_file"
    print_msg "$YELLOW" "⚠ Error collecting helm values, see $(basename "$output_file") for details"
  fi
}

# Function to collect pod information
collect_pods() {
  local output_file="$TMP_DIR/kubectl_pods.txt"
  print_msg "$YELLOW" "Collecting pod information..."

  {
    echo "Kubernetes Pods"
    echo "Namespace: $NAMESPACE"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
  } >"$output_file"

  if kubectl get pods -n "$NAMESPACE" -o wide >>"$output_file" 2>&1; then
    echo "" >>"$output_file"
    echo "----------------------------------------" >>"$output_file"
    echo "Pod Descriptions:" >>"$output_file"
    echo "----------------------------------------" >>"$output_file"

    # Get pod names safely
    local pod_names
    if pod_names=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); then
      for pod in $pod_names; do
        echo "" >>"$output_file"
        echo "=== Pod: $pod ===" >>"$output_file"
        kubectl describe pod "$pod" -n "$NAMESPACE" >>"$output_file" 2>&1 || true
        echo "" >>"$output_file"
      done
    fi
    print_msg "$GREEN" "✓ Pod information saved to $(basename "$output_file")"
  else
    print_msg "$YELLOW" "⚠ Error collecting pod information, see $(basename "$output_file") for details"
  fi
}

# Function to collect configmap information
collect_configmaps() {
  local output_file="$TMP_DIR/kubectl_configmaps.txt"
  print_msg "$YELLOW" "Collecting configmaps information..."

  {
    echo "Kubernetes ConfigMaps"
    echo "Namespace: $NAMESPACE"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
  } >"$output_file"

  if kubectl get configmap -n "$NAMESPACE" -o wide >>"$output_file" 2>&1; then
    echo "" >>"$output_file"
    echo "----------------------------------------" >>"$output_file"
    echo "ConfigMaps Descriptions:" >>"$output_file"
    echo "----------------------------------------" >>"$output_file"

    # Get cm names safely
    local configmap_names
    if configmap_names=$(kubectl get configmap -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); then
      for configmap in $configmap_names; do
        echo "" >>"$output_file"
        echo "=== ConfigMap: $configmap ===" >>"$output_file"
        kubectl get configmap "$configmap" -n "$NAMESPACE" -o yaml >>"$output_file" 2>&1 || true
        echo "" >>"$output_file"
      done
    fi
    print_msg "$GREEN" "✓ ConfigMaps information saved to $(basename "$output_file")"
  else
    print_msg "$YELLOW" "⚠ Error collecting ConfigMaps information, see $(basename "$output_file") for details"
  fi
}

# Function to collect logs from pods with specific labels
collect_pod_logs() {
  local logs_dir="$TMP_DIR/pod_logs"
  mkdir -p "$logs_dir"

  print_msg "$YELLOW" "Collecting pod logs for specific components..."

  # Define the labels to look for
  local labels=(
    "app.kubernetes.io/component=useradm"
    "app.kubernetes.io/component=tenantadm"
    "app.kubernetes.io/component=deployments"
  )

  local found_any=false

  for label in "${labels[@]}"; do
    local component=$(echo "$label" | cut -d'=' -f2)
    print_msg "$YELLOW" "  Checking for pods with label: $label"

    # Get pods with this label
    local pod_names
    if pod_names=$(kubectl get pods -n "$NAMESPACE" -l "$label" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); then
      if [[ -n "$pod_names" ]]; then
        found_any=true
        for pod in $pod_names; do
          local log_file="$logs_dir/${component}_${pod}.log"
          print_msg "$YELLOW" "    Collecting logs from pod: $pod"

          {
            echo "Pod: $pod"
            echo "Component: $component"
            echo "Namespace: $NAMESPACE"
            echo "Timestamp: $(date)"
            echo "----------------------------------------"
          } >"$log_file"

          # Get the logs (last 1000 lines by default, adjust as needed)
          if kubectl logs "$pod" -n "$NAMESPACE" --tail=1000 >>"$log_file" 2>&1; then
            print_msg "$GREEN" "    ✓ Logs saved for $pod"
          else
            # Try to get logs from previous container if current one failed
            echo "" >>"$log_file"
            echo "Note: Current container logs not available, trying previous container..." >>"$log_file"
            echo "----------------------------------------" >>"$log_file"
            if kubectl logs "$pod" -n "$NAMESPACE" --previous --tail=1000 >>"$log_file" 2>&1; then
              print_msg "$YELLOW" "    ⚠ Got previous container logs for $pod"
            else
              print_msg "$YELLOW" "    ⚠ Could not retrieve logs for $pod"
            fi
          fi
        done
      else
        print_msg "$YELLOW" "    No pods found with label: $label"
      fi
    fi
  done

  if [[ "$found_any" == true ]]; then
    print_msg "$GREEN" "✓ Pod logs collected in pod_logs directory"
  else
    print_msg "$YELLOW" "⚠ No pods found with the specified component labels"
    # Create a note file
    echo "No pods found with the following labels:" >"$logs_dir/NO_LOGS_FOUND.txt"
    for label in "${labels[@]}"; do
      echo "  - $label" >>"$logs_dir/NO_LOGS_FOUND.txt"
    done
  fi
}

# Function to create support bundle
create_support_bundle() {
  print_msg "$YELLOW" "Creating support bundle..."

  # Add a README file to the bundle
  cat >"$TMP_DIR/README.txt" <<EOF
Helm Support Bundle
===================
Generated: $(date)
Namespace: $NAMESPACE
Helm Release: $HELM_RELEASE

Contents:
- helm_history.txt: History of the Helm release
- helm_list.txt: List of all Helm releases in the namespace
- helm_values.yaml: Values used for the Helm release (secrets masked)
- kubectl_pods.txt: Pod information and descriptions
- pod_logs/: Directory containing logs from specific component pods
- README.txt: This file

Note: All sensitive information in helm_values.yaml has been masked with ***********
Note: Pod logs contain the last 1000 lines from each pod
EOF

  # Create the tarball
  tar -czf "$SUPPORT_BUNDLE" -C "$TMP_DIR" .

  print_msg "$GREEN" "✓ Support bundle created: $SUPPORT_BUNDLE"
  print_msg "$GREEN" "Bundle size: $(du -h "$SUPPORT_BUNDLE" | cut -f1)"
}

# Main function
main() {
  print_msg "$GREEN" "=== Mender Support Bundle Generator ==="
  echo ""

  # Check requirements
  check_requirements

  # Select namespace
  select_namespace

  # Select helm release
  select_helm_release

  # Create temporary directory
  create_tmp_dir

  # Collect information
  collect_helm_history
  collect_helm_list
  collect_helm_values
  collect_pods
  collect_configmaps
  collect_pod_logs

  # Create support bundle
  echo ""
  create_support_bundle

  echo ""
  print_msg "$GREEN" "=== Support bundle generation completed successfully ==="
  print_msg "$GREEN" "File: $SUPPORT_BUNDLE"
}

# Run main function
main
