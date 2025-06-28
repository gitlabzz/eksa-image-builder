#!/usr/bin/env bash
#
# ================================================================================
#  EKS Anywhere Image-Builder – RHEL 9.x bootstrap
#  Tested on: RHEL 9.3 GA (kernel 5.14)            Last update: 2025-06-28 (Rev-2)
# ================================================================================

set -euo pipefail

# -------------------------------------------------------------------------------
#  Globals & constants
# -------------------------------------------------------------------------------
readonly BUILDER_USERNAME="image-builder"
readonly ANSI_BOLD=$(tput bold || true)
readonly ANSI_RESET=$(tput sgr0  || true)

# -------------------------------------------------------------------------------
#  Logging helpers
# -------------------------------------------------------------------------------
log()       { printf '%s - INFO  - %s\n'  "$(date '+%F %T')" "$*"; }
log_warn()  { printf '%s - WARN  - %s\n'  "$(date '+%F %T')" "$*" >&2; }
log_error() { printf '%s - ERROR - %s\n' "$(date '+%F %T')" "$*" >&2; }

die() { log_error "$*"; exit 1; }

# -------------------------------------------------------------------------------
#  0. Preconditions
# -------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "Run this script as root (or with sudo -E)."

source /etc/os-release
[[ "$ID" == "rhel" || "$ID_LIKE" =~ rhel ]] || \
  die "Unsupported OS: this script targets RHEL 9.x."

# -------------------------------------------------------------------------------
#  1. Harden & tune SSH for Packer
# -------------------------------------------------------------------------------
configure_ssh() {
  log "[1] Ensuring sshd allows PasswordAuth + root login (needed by Packer)…"
  local cfg=/etc/ssh/sshd_config changed=0
  for rule in "PasswordAuthentication yes" "PermitRootLogin yes"; do
    if ! grep -Eq "^[[:space:]]*${rule}$" "$cfg"; then
      sed -Ei.bak "s/^(#\s*)?${rule%% *}.*/${rule}/" "$cfg"
      changed=1
    fi
  done
  (( changed )) && { systemctl restart sshd; log "[1] sshd restarted."; } \
                 || log "[1] sshd already set correctly."
}

# -------------------------------------------------------------------------------
#  2. Dedicated builder account
# -------------------------------------------------------------------------------
create_builder_user() {
  log "[2] Creating user “${BUILDER_USERNAME}”…"
  id "$BUILDER_USERNAME" &>/dev/null || {
    useradd -m -s /bin/bash "$BUILDER_USERNAME"
    passwd -d "$BUILDER_USERNAME"       # unlock, no password
  }

  usermod -aG wheel,libvirt,kvm "$BUILDER_USERNAME"

  local sudoers=/etc/sudoers.d/99-${BUILDER_USERNAME}-nopasswd
  echo "${BUILDER_USERNAME} ALL=(ALL) NOPASSWD: ALL" > "$sudoers"
  chmod 0440 "$sudoers"
  visudo -cf "$sudoers" || die "sudoers syntax error"

  install -d -o "$BUILDER_USERNAME" -g "$BUILDER_USERNAME" -m 700 \
           "/home/${BUILDER_USERNAME}/.ssh"
  : > "/home/${BUILDER_USERNAME}/.ssh/authorized_keys"
  chmod 600 "/home/${BUILDER_USERNAME}/.ssh/authorized_keys"
}

# -------------------------------------------------------------------------------
#  3. System repos & base tooling
# -------------------------------------------------------------------------------
enable_repos_and_base_pkgs() {
  log "[3] Enabling CodeReady Builder (CRB)…"
  if subscription-manager identity &>/dev/null; then
    subscription-manager repos --enable \
        "codeready-builder-for-rhel-9-$(arch)-rpms" \
      || log_warn "Could not enable CRB (check subscription)."
  else
    log_warn "Host not registered – skipping CRB enablement."
  fi

  log "[3] Installing EPEL release…"
  dnf -y install \
      "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"

  dnf -y install dnf-plugins-core
  dnf -qy makecache

  log "[3] Installing core build/runtime packages…"
  dnf -y install \
        jq make tar gzip unzip               \
        curl wget git                        \
        python3-pip python3-devel            \
        qemu-kvm virt-install                \
        libvirt libvirt-daemon-driver-qemu   \
        libguestfs-tools osinfo-db-tools     \
        haveged                              \
        >/dev/null

  systemctl enable --now haveged.service        || true
  systemctl enable --now virtqemud.socket virtlogd.socket >/dev/null

  log "[3] Package staging complete."
}

# -------------------------------------------------------------------------------
#  4. Builder-scoped tasks (runs as image-builder)
# -------------------------------------------------------------------------------
run_as_builder() {
  local download_iso_flag="${DOWNLOAD_ISO:-${DOWNLOAD_UBUNTU_ISO:-false}}"

  sudo -iu "$BUILDER_USERNAME" env DOWNLOAD_ISO="$download_iso_flag" bash -- <<'EOSU'
set -euo pipefail
trap 'echo "$(date "+%F %T") - ERROR (builder) - Unexpected failure." >&2' ERR

log_b() { printf '%s - INFO  (builder) - %s\n'  "$(date '+%F %T')" "$*"; }
die_b() { printf '%s - ERROR (builder) - %s\n' "$(date '+%F %T')" "$*" >&2; exit 1; }

# Make /usr/local/bin available immediately (Ansible, yq, image-builder)
export PATH="/usr/local/bin:$PATH"
grep -q 'export PATH=.*/usr/local/bin' ~/.bashrc || \
  echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc

# --- 3-A  Env prep -------------------------------------------------------------
log_b "[3-A] Setting EKSA_SKIP_VALIDATE_DEPENDENCIES"
grep -q EKSA_SKIP_VALIDATE_DEPENDENCIES ~/.bashrc || \
  echo 'export EKSA_SKIP_VALIDATE_DEPENDENCIES=true' >> ~/.bashrc
export EKSA_SKIP_VALIDATE_DEPENDENCIES=true

log_b "[3-A] Installing Ansible 2.15.13 via pip…"
sudo dnf -qy remove ansible-core || true
sudo python3 -m pip install --upgrade pip >/dev/null
sudo python3 -m pip install ansible-core==2.15.13 >/dev/null

log_b "[3-A] Installing yq binary…"
if ! command -v yq &>/dev/null; then
  YQ_VERSION=v4.44.1
  wget -q "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" \
       -O /tmp/yq && chmod +x /tmp/yq && sudo mv /tmp/yq /usr/local/bin/
fi

# --- 3-B  Validate virtualization ---------------------------------------------
log_b "[3-B] Verifying hardware virt…"
grep -Eq '(vmx|svm)' /proc/cpuinfo || die_b "CPU lacks virtualization flags."
test -c /dev/kvm                 || die_b "/dev/kvm not present."

# --- 3-C  Patch EKS-A helper (idempotent) -------------------------------------
PATCH="$HOME/eks-anywhere-build-tooling/projects/kubernetes-sigs/image-builder/image-builder/images/capi/hack/ensure-ansible.sh"
if [[ -f "$PATCH" ]] && ! grep -q 'raw_version=' "$PATCH"; then
  log_b "Patching ensure-ansible.sh for modern version strings…"
  sudo sed -i \
   's/ansible_version=($(ansible --version | head -1))/raw_version=$(ansible --version 2>\/dev\/null | head -1)\
if [[ "$raw_version" =~ "[" ]]; then\
  ansible_version=($(echo "$raw_version" | awk -F"[][]" "{print \$2}"))\
else\
  ansible_version=($raw_version)\
fi/' "$PATCH"
fi

# --- 4  Install image-builder CLI ---------------------------------------------
log_b "[4] Installing AWS image-builder CLI…"
if ! command -v image-builder &>/dev/null; then
  tmp=$(mktemp -d)
  EKSA_RELEASE=$(curl -sL https://anywhere-assets.eks.amazonaws.com/releases/eks-a/manifest.yaml \
                 | yq '.spec.latestVersion')
  BUNDLE_URL=$(curl -sL https://anywhere-assets.eks.amazonaws.com/releases/eks-a/manifest.yaml \
               | yq ".spec.releases[] | select(.version==\"${EKSA_RELEASE}\").bundleManifestUrl")
  TARBALL=$(curl -sL "$BUNDLE_URL" \
               | yq '.spec.versionsBundles[0].eksD.imagebuilder.uri')

  curl -sL "$TARBALL" | tar xzf - -C "$tmp"
  bin_path=$(find "$tmp" -type f -name image-builder -perm -u+x | head -n1)
  [[ -n "$bin_path" ]] || die_b "image-builder binary not found in tarball"
  sudo install -m0755 "$bin_path" /usr/local/bin/image-builder
  rm -rf "$tmp"
fi
image-builder version >/dev/null || die_b "image-builder install failed."

# --- 5  (optional) ISO fetch & metadata ---------------------------------------
if [[ "${DOWNLOAD_ISO:-false}" == "true" ]]; then
  log_b "[5] Downloading Ubuntu 22.04.5 ISO…"
  ISO="ubuntu-22.04.5-live-server-amd64.iso"
  URL="https://releases.ubuntu.com/22.04.5/${ISO}"
  SHA256_EXPECTED="9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"

  cd "$HOME"
  [[ -f $ISO ]] || wget -q "$URL" -O "$ISO"
  sha=$(sha256sum "$ISO" | awk '{print $1}')
  [[ "$sha" == "$SHA256_EXPECTED" ]] || die_b "ISO checksum mismatch."

  jq -n --arg url "file://$HOME/$ISO" \
        --arg sum "$SHA256_EXPECTED" \
        --arg type sha256 \
        '{iso_url:$url,iso_checksum:$sum,iso_checksum_type:$type}' \
        > baremetal-ubuntu.json
fi

log_b "Builder-side tasks finished successfully."
EOSU
}

# -------------------------------------------------------------------------------
#  Main
# -------------------------------------------------------------------------------
main() {
  configure_ssh
  enable_repos_and_base_pkgs   # must precede user creation (creates libvirt group)
  create_builder_user
  run_as_builder
  log "Bootstrap finished ${ANSI_BOLD}successfully${ANSI_RESET}."
}

main "$@"
