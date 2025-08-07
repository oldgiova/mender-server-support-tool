#!/bin/bash

set -euo pipefail

# Global variables
TMP_DIR=""
NAMESPACE=""
HELM_RELEASE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SUPPORT_BUNDLE="mender_support_${TIMESTAMP}.tar.gz"
MASK_SECRETS="${MASK_SECRETS:-true}" # Can be disabled with MASK_SECRETS=false
MAX_LOG_LINES="${MAX_LOG_LINES:-1000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Security: Set restrictive umask
umask 077

# Cleanup function
cleanup() {
  local exit_code=$?
  echo -e "\n${YELLOW}Cleaning up...${NC}"
  if [[ -n "$TMP_DIR" ]] && [[ -d "$TMP_DIR" ]]; then
    # Securely remove temporary directory
    find "$TMP_DIR" -type f -exec shred -vfz {} \; 2>/dev/null || true
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

# Function to check if a command exists and is in a secure location
check_command() {
  local cmd=$1
  local cmd_path

  if ! cmd_path=$(command -v "$cmd" 2>/dev/null); then
    print_msg "$RED" "Error: $cmd is not installed or not in PATH"
    return 1
  fi

  # Security: Warn if command is not in standard system paths
  case "$cmd_path" in
  /usr/bin/* | /usr/local/bin/* | /bin/* | /sbin/* | /usr/sbin/*)
    print_msg "$GREEN" "✓ $cmd is installed at $cmd_path"
    ;;
  *)
    print_msg "$YELLOW" "⚠ Warning: $cmd is installed in non-standard location: $cmd_path"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      return 1
    fi
    ;;
  esac
  return 0
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

# Function to validate namespace name (security: prevent injection)
validate_name() {
  local name=$1
  local type=$2

  # Allow only alphanumeric, dash, underscore, and dot
  if [[ ! "$name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    print_msg "$RED" "Error: Invalid $type name. Contains forbidden characters."
    exit 1
  fi

  # Prevent directory traversal
  if [[ "$name" == *".."* ]]; then
    print_msg "$RED" "Error: Invalid $type name. Directory traversal detected."
    exit 1
  fi
}

# Function to select namespace
select_namespace() {
  print_msg "$YELLOW" "Fetching available namespaces..."

  # Get namespaces and store in array (safe from word splitting)
  local namespaces=()
  while IFS= read -r ns; do
    namespaces+=("$ns")
  done < <(kubectl get ns -o json | jq -r '.items[].metadata.name' | sort)

  if [[ ${#namespaces[@]} -eq 0 ]]; then
    print_msg "$RED" "No namespaces found"
    exit 1
  fi

  print_msg "$GREEN" "Available namespaces:"
  for i in "${!namespaces[@]}"; do
    printf "%3d) %s\n" $((i + 1)) "${namespaces[$i]}"
  done

  while true; do
    read -p "Select namespace (1-${#namespaces[@]}): " selection
    if [[ "$selection" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#namespaces[@]})); then
      NAMESPACE="${namespaces[$((selection - 1))]}"
      validate_name "$NAMESPACE" "namespace"
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

  # Get helm releases in the selected namespace (safe from word splitting)
  local releases=()
  while IFS= read -r release; do
    releases+=("$release")
  done < <(helm ls -n "$NAMESPACE" -o json | jq -r '.[].name' | sort)

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
      validate_name "$HELM_RELEASE" "release"
      print_msg "$GREEN" "Selected Helm release: $HELM_RELEASE"
      echo ""
      break
    else
      print_msg "$RED" "Invalid selection. Please try again."
    fi
  done
}

# Function to create temporary directory with secure permissions
create_tmp_dir() {
  print_msg "$YELLOW" "Creating temporary directory..."
  # Security: Create temp dir with restricted permissions (700)
  TMP_DIR=$(mktemp -d -t mender-support-XXXXXX)
  chmod 700 "$TMP_DIR"
  print_msg "$GREEN" "Temporary directory created: $TMP_DIR (mode 700)"
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
    chmod 600 "$output_file"
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
    chmod 600 "$output_file"
    print_msg "$GREEN" "✓ Helm list saved to $(basename "$output_file")"
  else
    print_msg "$YELLOW" "⚠ Error collecting helm list, see $(basename "$output_file") for details"
  fi
}

# Enhanced function to mask secrets in values
mask_secrets() {
  if [[ "$MASK_SECRETS" != "true" ]]; then
    cat
    return
  fi

  # More comprehensive secret masking
  sed -E \
    -e 's/(password[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(passwd["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(pwd["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(secret[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(token[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(api[_-]?key[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(api[_-]?secret[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(access[_-]?key[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(private[_-]?key[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(credential[s]?["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(auth["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(authorization["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(bearer["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/(jwt["\s]*:["\s]*)[^"\s,}]+/\1***********/gi' \
    -e 's/([a-zA-Z0-9+\/]{40,}=*)/***BASE64_CONTENT***/g' \
    -e 's/(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)/\1***CERTIFICATE_CONTENT***\2/g' \
    -e 's/(Bearer\s+)[^\s]+/\1***********/gi' \
    -e 's/(aws_access\s+)[^\s]+/\1***********/gi' \
    -e 's/(aws_secret\s+)[^\s]+/\1***********/gi' \
    -e 's/(Basic\s+)[^\s]+/\1***********/gi'
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
    chmod 600 "$output_file"
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
    chmod 600 "$output_file"
    print_msg "$YELLOW" "⚠ Error collecting helm values, see $(basename "$output_file") for details"
  fi
}

# Function to collect pod information (with secret masking)
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

    # Get pod names safely (prevent word splitting)
    local pod_names=()
    while IFS= read -r pod; do
      [[ -n "$pod" ]] && pod_names+=("$pod")
    done < <(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n')

    for pod in "${pod_names[@]}"; do
      echo "" >>"$output_file"
      echo "=== Pod: $pod ===" >>"$output_file"
      # Mask environment variables and other secrets in pod descriptions
      kubectl describe pod "$pod" -n "$NAMESPACE" 2>&1 | mask_secrets >>"$output_file" || true
      echo "" >>"$output_file"
    done
    chmod 600 "$output_file"
    print_msg "$GREEN" "✓ Pod information saved to $(basename "$output_file")"
  else
    chmod 600 "$output_file"
    print_msg "$YELLOW" "⚠ Error collecting pod information, see $(basename "$output_file") for details"
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
          if kubectl logs "$pod" -n "$NAMESPACE" --tail=1000 | grep -v 'health\|alive' >>"$log_file" 2>&1; then
            print_msg "$GREEN" "    ✓ Logs saved for $pod"
          else
            # Try to get logs from previous container if current one failed
            echo "" >>"$log_file"
            echo "Note: Current container logs not available, trying previous container..." >>"$log_file"
            echo "----------------------------------------" >>"$log_file"
            if kubectl logs "$pod" -n "$NAMESPACE" --previous --tail=1000 | grep -v 'health\|alive' >>"$log_file" 2>&1; then
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

# Function to collect ConfigMaps with content
collect_configmaps() {
  local output_file="$TMP_DIR/configmaps.yaml"
  print_msg "$YELLOW" "Collecting ConfigMaps from namespace '$NAMESPACE'..."

  {
    echo "# ConfigMaps in namespace: $NAMESPACE"
    echo "# Timestamp: $(date)"
    echo "# Note: ConfigMap contents may contain sensitive data"
    echo "# ============================================"
    echo ""
  } >"$output_file"

  # Get list of ConfigMaps (safe from word splitting)
  local configmaps=()
  while IFS= read -r cm; do
    [[ -n "$cm" ]] && configmaps+=("$cm")
  done < <(kubectl get configmaps -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n')

  if [[ ${#configmaps[@]} -eq 0 ]]; then
    echo "No ConfigMaps found in namespace '$NAMESPACE'" >>"$output_file"
    chmod 600 "$output_file"
    print_msg "$YELLOW" "⚠ No ConfigMaps found in namespace"
    return
  fi

  print_msg "$GREEN" "Found ${#configmaps[@]} ConfigMap(s)"

  for cm in "${configmaps[@]}"; do
    print_msg "$YELLOW" "  Processing ConfigMap: $cm"
    {
      echo "---"
      echo "# ConfigMap: $cm"
      echo "# ----------------------------------------"
    } >>"$output_file"

    # Get the ConfigMap in YAML format and mask secrets if enabled
    if kubectl get configmap "$cm" -n "$NAMESPACE" -o yaml 2>&1 | mask_secrets >>"$output_file"; then
      echo "" >>"$output_file"
      print_msg "$GREEN" "    ✓ ConfigMap '$cm' collected"
    else
      echo "# Error retrieving ConfigMap: $cm" >>"$output_file"
      print_msg "$YELLOW" "    ⚠ Error collecting ConfigMap '$cm'"
    fi
  done

  chmod 600 "$output_file"
  print_msg "$GREEN" "✓ ConfigMaps saved to $(basename "$output_file")"
}

# Function to list Secrets (without content)
collect_secrets_list() {
  local output_file="$TMP_DIR/secrets_list.txt"
  print_msg "$YELLOW" "Collecting list of Secrets from namespace '$NAMESPACE'..."

  {
    echo "Secrets List (metadata only - no sensitive content)"
    echo "Namespace: $NAMESPACE"
    echo "Timestamp: $(date)"
    echo "============================================"
    echo ""
    echo "SECURITY NOTE: Secret contents are NOT included in this file."
    echo "Only metadata (name, type, creation time, size) is collected."
    echo ""
    echo "============================================"
    echo ""
  } >"$output_file"

  # Get detailed list of secrets without the actual data
  echo "SECRET NAME                          TYPE                                  DATA   CREATED" >>"$output_file"
  echo "---------------------------------------------------------------------------------------------------" >>"$output_file"

  # Get secrets with details but without actual secret data
  if kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
    jq -r '.items[] | 
            "\(.metadata.name)|\(.type)|
            \(.data | if . then (. | keys | length) else 0 end)|
            \(.metadata.creationTimestamp)"' |
    while IFS='|' read -r name type data_count created; do
      # Format output without age calculation to avoid date parsing issues
      printf "%-36s %-36s %-6s %s\n" \
        "$name" \
        "$type" \
        "$data_count" \
        "$created"
    done >>"$output_file"; then

    echo "" >>"$output_file"
    echo "============================================" >>"$output_file"
    echo "Summary:" >>"$output_file"

    # Count secrets by type
    echo "" >>"$output_file"
    echo "Secrets by Type:" >>"$output_file"
    kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
      jq -r '.items[].type' | sort | uniq -c |
      while read count type; do
        printf "  %3d x %s\n" "$count" "$type"
      done >>"$output_file"

    # Total count - ensure integer
    local total_secrets
    total_secrets=$(kubectl get secrets -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    total_secrets=${total_secrets:-0}
    echo "" >>"$output_file"
    echo "Total Secrets: $total_secrets" >>"$output_file"

    # Check for potentially problematic secrets
    echo "" >>"$output_file"
    echo "Security Observations:" >>"$output_file"

    # Check for default service account tokens - ensure integer
    local default_tokens
    default_tokens=$(kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
      jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | .metadata.name' |
      grep -c "^default-token" || echo "0")
    default_tokens=$(echo "$default_tokens" | tr -d ' ')
    default_tokens=${default_tokens:-0}

    if [ "$default_tokens" -gt 0 ] 2>/dev/null; then
      echo "  - Found $default_tokens default service account token(s)" >>"$output_file"
    fi

    # Check for Opaque secrets - ensure integer
    local opaque_secrets
    opaque_secrets=$(kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
      jq -r '.items[] | select(.type == "Opaque") | .metadata.name' | wc -l | tr -d ' ')
    opaque_secrets=${opaque_secrets:-0}

    if [ "$opaque_secrets" -gt 0 ] 2>/dev/null; then
      echo "  - Found $opaque_secrets Opaque secret(s) (may contain credentials)" >>"$output_file"
    fi

    # Check for TLS secrets - ensure integer
    local tls_secrets
    tls_secrets=$(kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
      jq -r '.items[] | select(.type == "kubernetes.io/tls") | .metadata.name' | wc -l | tr -d ' ')
    tls_secrets=${tls_secrets:-0}

    if [ "$tls_secrets" -gt 0 ] 2>/dev/null; then
      echo "  - Found $tls_secrets TLS certificate secret(s)" >>"$output_file"
    fi

    # Check for docker registry secrets - ensure integer
    local registry_secrets
    registry_secrets=$(kubectl get secrets -n "$NAMESPACE" -o json 2>/dev/null |
      jq -r '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | .metadata.name' | wc -l | tr -d ' ')
    registry_secrets=${registry_secrets:-0}

    if [ "$registry_secrets" -gt 0 ] 2>/dev/null; then
      echo "  - Found $registry_secrets Docker registry credential secret(s)" >>"$output_file"
    fi

    chmod 600 "$output_file"
    print_msg "$GREEN" "✓ Secrets list saved to $(basename "$output_file") (metadata only, no sensitive content)"
  else
    echo "Error retrieving secrets list" >>"$output_file"
    chmod 600 "$output_file"
    print_msg "$YELLOW" "⚠ Error collecting secrets list"
  fi
}

# Function to create support bundle
create_support_bundle() {
  print_msg "$YELLOW" "Creating support bundle..."

  # Add a README file to the bundle
  cat >"$TMP_DIR/README.txt" <<EOF
Mender Server Support Bundle
===================
Generated: $(date)
Namespace: $NAMESPACE
Helm Release: $HELM_RELEASE
Secrets Masked: $MASK_SECRETS

Contents:
- helm_history.txt: History of the Helm release
- helm_list.txt: List of all Helm releases in the namespace
- helm_values.yaml: Values used for the Helm release (secrets masked: $MASK_SECRETS)
- kubectl_pods.txt: Pod information and descriptions
- pod_logs/: Directory containing logs from specific component pods
  * useradm pods (app.kubernetes.io/component=useradm)
  * tenantadm pods (app.kubernetes.io/component=tenantadm)
  * deployments pods (app.kubernetes.io/component=deployments)
- configmaps.yaml: All ConfigMaps in the namespace with their content (secrets masked: $MASK_SECRETS)
- secrets_list.txt: List of all Secrets in the namespace (METADATA ONLY - no secret values)
- README.txt: This file

Security Notes:
- All sensitive information has been masked with *********** if MASK_SECRETS=true
- ConfigMap contents are included but may contain configuration data
- Secret VALUES are NOT included - only metadata (name, type, age, data count)
- Pod logs contain the last $MAX_LOG_LINES lines from each pod
- This bundle may still contain sensitive information - handle with care
- Recommended: Transfer using encrypted channels only
- Recommended: Delete after use with secure deletion (shred -vfz)

File Permissions:
- All files created with mode 600 (owner read/write only)
- Bundle created with mode 600
- Temporary directory created with mode 700
EOF
  chmod 600 "$TMP_DIR/README.txt"

  # Create the tarball with restricted permissions
  tar -czf "$SUPPORT_BUNDLE" -C "$TMP_DIR" .
  chmod 600 "$SUPPORT_BUNDLE"

  print_msg "$GREEN" "✓ Support bundle created: $SUPPORT_BUNDLE (mode 600)"
  print_msg "$GREEN" "Bundle size: $(du -h "$SUPPORT_BUNDLE" | cut -f1)"
  print_msg "$YELLOW" "⚠ Security: Bundle contains potentially sensitive data. Handle with care!"
}

# Function to show security warning
show_security_warning() {
  print_msg "$YELLOW" "╔══════════════════════════════════════════════════════════════╗"
  print_msg "$YELLOW" "║                    SECURITY NOTICE                          ║"
  print_msg "$YELLOW" "╠══════════════════════════════════════════════════════════════╣"
  print_msg "$YELLOW" "║ This script collects potentially sensitive information.     ║"
  print_msg "$YELLOW" "║                                                              ║"
  print_msg "$YELLOW" "║ The support bundle may contain:                             ║"
  print_msg "$YELLOW" "║ - Configuration values (secrets are masked by default)      ║"
  print_msg "$YELLOW" "║ - Pod logs (may contain sensitive application data)         ║"
  print_msg "$YELLOW" "║ - Cluster information                                       ║"
  print_msg "$YELLOW" "║                                                              ║"
  print_msg "$YELLOW" "║ Security measures in place:                                 ║"
  print_msg "$YELLOW" "║ - Temporary files created with mode 700                     ║"
  print_msg "$YELLOW" "║ - Output files created with mode 600                        ║"
  print_msg "$YELLOW" "║ - Secrets masked in values and logs (if enabled)            ║"
  print_msg "$YELLOW" "║ - Secure deletion of temp files on exit                     ║"
  print_msg "$YELLOW" "║                                                              ║"
  print_msg "$YELLOW" "║ Recommendations:                                            ║"
  print_msg "$YELLOW" "║ - Review the bundle contents before sharing                 ║"
  print_msg "$YELLOW" "║ - Transfer using encrypted channels only                    ║"
  print_msg "$YELLOW" "║ - Delete with: shred -vfz support_*.tar.gz                  ║"
  print_msg "$YELLOW" "╚══════════════════════════════════════════════════════════════╝"
  echo ""

  read -p "Do you understand and want to proceed? (y/N): " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_msg "$RED" "Aborted by user"
    exit 1
  fi
  echo ""
}

# Main function
main() {
  print_msg "$GREEN" "=== Helm Support Bundle Generator ==="
  echo ""

  # Show security warning
  show_security_warning

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
  collect_pod_logs
  collect_configmaps
  collect_secrets_list

  # Create support bundle
  echo ""
  create_support_bundle

  echo ""
  print_msg "$GREEN" "=== Support bundle generation completed successfully ==="
  print_msg "$GREEN" "File: $SUPPORT_BUNDLE"
  print_msg "$YELLOW" "Remember to:"
  print_msg "$YELLOW" "  1. Review contents before sharing"
  print_msg "$YELLOW" "  2. Transfer securely (encrypted channel)"
  print_msg "$YELLOW" "  3. Delete securely when done: shred -vfz $SUPPORT_BUNDLE"
}

# Run main function
main
