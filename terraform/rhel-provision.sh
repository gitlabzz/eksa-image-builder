#!/bin/bash
#
# =================================================================================
# EKS Anywhere Image Builder - RHEL 9.x Setup Script
# =================================================================================

# --- Script Configuration ---
set -euo pipefail

# --- Globals ---
readonly BUILDER_USERNAME="image-builder"

# --- Logging Functions ---
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - INFO - $1"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ERROR - $1" >&2
    exit 1
}

# =================================================================================
# STEP 1: CONFIGURE SYSTEM-WIDE SSH SETTINGS
# =================================================================================
configure_ssh() {
    log "[Step 1] Configuring system-wide SSH for Packer compatibility..."
    local ssh_config_file="/etc/ssh/sshd_config"
    local needs_restart=false
    if grep -qE '^PasswordAuthentication\s+yes$' "$ssh_config_file" && grep -qE '^PermitRootLogin\s+yes$' "$ssh_config_file"; then
        log "[Step 1] SSH is already configured correctly. Skipping."
        return
    fi
    log "[Step 1] Updating SSH configuration..."
    sudo sed -i.bak -E 's/^(#\s*)?PasswordAuthentication\s+.*/PasswordAuthentication yes/' "$ssh_config_file"
    sudo sed -i -E 's/^(#\s*)?PermitRootLogin\s+.*/PermitRootLogin yes/' "$ssh_config_file"
    needs_restart=true
    log "[Step 1] Validating SSH configuration..."
    if ! sudo grep -qE '^PasswordAuthentication\s+yes$' "$ssh_config_file" || ! sudo grep -qE '^PermitRootLogin\s+yes$' "$ssh_config_file"; then
        error_exit "[Step 1] Validation failed. SSH configuration is incorrect."
    fi
    log "[Step 1] Validation successful."
    if [[ "$needs_restart" == true ]]; then
        log "[Step 1] Restarting sshd service to apply changes..."
        sudo systemctl restart sshd || error_exit "[Step 1] Failed to restart sshd service."
        log "[Step 1] sshd service restarted successfully."
    fi
}

# =================================================================================
# STEP 2: CREATE THE DEDICATED BUILDER ACCOUNT
# =================================================================================
create_builder_user() {
    log "[Step 2] Creating dedicated builder account '$BUILDER_USERNAME'..."
    if id "$BUILDER_USERNAME" &>/dev/null; then
        log "[Step 2] User '$BUILDER_USERNAME' already exists. Skipping creation."
    else
        log "[Step 2] User '$BUILDER_USERNAME' not found. Creating..."
        sudo useradd -m -s /bin/bash "$BUILDER_USERNAME" || error_exit "[Step 2] Failed to create user '$BUILDER_USERNAME'."
        sudo passwd -d "$BUILDER_USERNAME"  # Remove password but keep account enabled
        log "[Step 2] Successfully created user '$BUILDER_USERNAME'."
    fi
    if groups "$BUILDER_USERNAME" | grep -q '\bwheel\b'; then
        log "[Step 2] User '$BUILDER_USERNAME' is already in the 'wheel' group. Skipping."
    else
        log "[Step 2] Adding user '$BUILDER_USERNAME' to the 'wheel' group..."
        sudo usermod -aG wheel "$BUILDER_USERNAME" || error_exit "[Step 2] Failed to add user to 'wheel' group."
    fi
    log "[Step 2] Configuring passwordless sudo for '$BUILDER_USERNAME'..."
    local sudoer_file="/etc/sudoers.d/99-${BUILDER_USERNAME}-nopasswd"
    local sudoer_config="${BUILDER_USERNAME} ALL=(ALL) NOPASSWD: ALL"
    if [ -f "$sudoer_file" ] && grep -qF "$sudoer_config" "$sudoer_file"; then
        log "[Step 2] Passwordless sudo is already configured. Skipping."
    else
        log "[Step 2] Creating sudoers file at $sudoer_file"
        echo "$sudoer_config" | sudo tee "$sudoer_file" > /dev/null
        sudo chmod 0440 "$sudoer_file"
        sudo visudo -c -f "$sudoer_file" || error_exit "[Step 2] Failed to validate new sudoers file. Please check syntax."
        log "[Step 2] Successfully configured passwordless sudo."
    fi
    local ssh_dir="/home/$BUILDER_USERNAME/.ssh"
    log "[Step 2] Ensuring SSH directory exists and has correct permissions..."
    sudo mkdir -p "$ssh_dir"
    sudo touch "$ssh_dir/authorized_keys"
    sudo chown -R "${BUILDER_USERNAME}:${BUILDER_USERNAME}" "$ssh_dir"
    sudo chmod 700 "$ssh_dir"
    sudo chmod 600 "$ssh_dir/authorized_keys"
}

# =================================================================================
# STEPS 3, 4, 5: RUN ALL SETUP STEPS AS THE BUILDER USER
# =================================================================================
run_user_scope_steps() {
    log "Switching to '$BUILDER_USERNAME' to run user-scoped setup steps..."

    # Preserve the DOWNLOAD_ISO environment variable
    local download_iso_flag="${DOWNLOAD_ISO:-false}"

    sudo -iu "$BUILDER_USERNAME" env DOWNLOAD_ISO="$download_iso_flag" bash -s <<'EOF'
        set -euo pipefail

        # FIX: Remove 'local' from top-level variable assignment
        iso_download_flag="${DOWNLOAD_ISO:-false}"

        log_user() {
            echo "$(date +'%Y-%m-%d %H:%M:%S') - INFO (as image-builder) - $1"
        }

        error_exit_user() {
            echo "$(date +'%Y-%m-%d %H:%M:%S') - ERROR (as image-builder) - $1" >&2
            exit 1
        }

        # --- Definition for Step 3 ---
        run_step_3() {
            log_user "--- Starting Step 3: Prepare Builder Environment ---"
            log_user "[3.1] Configuring EKSA_SKIP_VALIDATE_DEPENDENCIES..."
            if ! grep -q "EKSA_SKIP_VALIDATE_DEPENDENCIES" ~/.bashrc; then
                echo 'export EKSA_SKIP_VALIDATE_DEPENDENCIES=true' >> ~/.bashrc
            fi
            export EKSA_SKIP_VALIDATE_DEPENDENCIES=true

            # Handle RHEL subscription status
            log_user "[3.2] Checking system registration status..."
            if ! sudo subscription-manager status; then
                log_user "WARN: System not registered with Red Hat. Continuing with public repos..."
            fi

            log_user "[3.3] Installing required packages..."

            # Install EPEL first
            if ! rpm -q epel-release; then
                log_user "Installing EPEL repository..."
                sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
            fi

            # Update metadata
            sudo dnf makecache -y

            # Install packages
            log_user "Installing main application packages..."
            sudo dnf install -y jq make python3-pip qemu-kvm libvirt virt-install libguestfs-tools libosinfo unzip git

            # Install entropy generator
            if sudo dnf list haveged &>/dev/null; then
                sudo dnf install -y haveged
                sudo systemctl enable --now haveged
            else
                log_user "WARN: haveged not available. Using rng-tools."
                sudo dnf install -y rng-tools
                sudo systemctl enable --now rngd
            fi

            log_user "Enabling and starting libvirtd..."
            sudo systemctl enable --now libvirtd

            log_user "Installing yq from GitHub release..."
            YQ_VERSION="v4.44.1"
            if ! command -v yq &> /dev/null; then
                wget -q "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" -O yq
                chmod +x yq
                sudo mv yq /usr/local/bin
            fi

            # Install specific ansible-core version
            log_user "Ensuring correct Ansible version for EKS-A..."
            sudo dnf remove -y ansible-core || true
            sudo pip3 install ansible-core==2.15.13

            # Patch EKS-A script if available
            log_user "Attempting to patch EKS-A 'ensure-ansible.sh' script..."
            local patch_script_path="/home/$USER/eks-anywhere-build-tooling/projects/kubernetes-sigs/image-builder/image-builder/images/capi/hack/ensure-ansible.sh"
            if [ -f "$patch_script_path" ]; then
                if grep -q "raw_version=" "$patch_script_path"; then
                    log_user "Ansible patch script already patched. Skipping."
                else
                    log_user "Patching '$patch_script_path'..."
                    sudo sed -i 's/ansible_version=($(ansible --version | head -1))/raw_version=$(ansible --version 2>\/dev\/null | head -1)\nif [[ "$raw_version" =~ "[" ]]; then\n  ansible_version=($(echo "$raw_version" | awk -F'"'"'[][]'"'"' '"'"'{print $2}'"'"'))\nelse\n  ansible_version=($raw_version)\nfi/' "$patch_script_path"
                    log_user "Patch applied."
                fi
            else
                log_user "WARN: EKS-A ansible patch script not found."
            fi

            log_user "[3.4] Configuring KVM access and SSH..."
            if ! groups | grep -q '\bkvm\b'; then
                sudo usermod -aG kvm "$(whoami)"
            fi
            if ! groups | grep -q '\blibvirt\b'; then
                sudo usermod -aG libvirt "$(whoami)"
            fi
            sudo chmod 666 /dev/kvm && sudo chown root:kvm /dev/kvm
            mkdir -p ~/.ssh
            if ! grep -q "HostKeyAlgorithms" ~/.ssh/config &>/dev/null; then
                printf 'HostKeyAlgorithms +ssh-rsa\nPubkeyAcceptedKeyTypes +ssh-rsa\n' >> ~/.ssh/config
                chmod 600 ~/.ssh/config
            fi

            log_user "--- Running validation for Step 3 ---"
            log_user "Validating KVM acceleration..."
            if ! [ -c /dev/kvm ] || ! grep -q -E '(vmx|svm)' /proc/cpuinfo; then
                error_exit_user "Validation FAILED: KVM acceleration cannot be used."
            else
                log_user "Validation PASSED: KVM acceleration can be used."
            fi

            log_user "Validating Ansible version (expecting core 2.15.13)..."
            local ansible_version_output
            ansible_version_output=$(ansible --version | head -n 1)
            if ! echo "$ansible_version_output" | grep -q '\[core 2\.15\.13\]'; then
                error_exit_user "Validation FAILED: Ansible version is not 2.15.13. Found: $ansible_version_output"
            fi
            log_user "Validation PASSED: Ansible version is correct ($ansible_version_output)."
            log_user "Validating yq version (expecting v4.x)..."
            if ! yq --version | grep -q 'version v4\.'; then
                error_exit_user "Validation FAILED: yq version is not 4.x."
            fi
            log_user "Validation PASSED: yq version is 4.x."
            log_user "--- Finished Step 3 ---"
        }

        # --- Definition for Step 4 ---
        run_step_4() {
            log_user "--- Starting Step 4: Install EKS Anywhere Image Builder CLI ---"
            if command -v image-builder &> /dev/null; then
                log_user "image-builder command already found. Skipping installation."
            else
                cd /tmp
                EKSA_RELEASE_VERSION=$(curl -sL https://anywhere-assets.eks.amazonaws.com/releases/eks-a/manifest.yaml | yq '.spec.latestVersion')
                BUNDLE_MANIFEST_URL=$(curl -sL https://anywhere-assets.eks.amazonaws.com/releases/eks-a/manifest.yaml | yq ".spec.releases[] | select(.version==\"$EKSA_RELEASE_VERSION\").bundleManifestUrl")
                IMAGEBUILDER_TARBALL_URI=$(curl -sL "$BUNDLE_MANIFEST_URL" | yq '.spec.versionsBundles[0].eksD.imagebuilder.uri')
                curl -sL "$IMAGEBUILDER_TARBALL_URI" | tar xz ./image-builder
                sudo install -m 0755 image-builder /usr/local/bin/image-builder
                cd ~
            fi
            log_user "--- Running validation for Step 4 ---"
            if ! image-builder version | grep -qE '^v[0-9]+\.[0-9]+'; then
                error_exit_user "Validation FAILED: image-builder validation failed"
            fi
            log_user "Validation PASSED: image-builder is installed and version is valid."
            log_user "--- Finished Step 4 ---"
        }

        # --- Definition for Step 5 ---
        run_step_5() {
            log_user "--- Starting Step 5: Download Ubuntu ISO and Create Metadata ---"
            local iso_filename="ubuntu-22.04.5-live-server-amd64.iso"
            local iso_url="https://releases.ubuntu.com/22.04.5/ubuntu-22.04.5-live-server-amd64.iso"
            local json_filename="baremetal-ubuntu.json"
            local expected_checksum="9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
            cd ~
            if [ -f "$iso_filename" ]; then
                log_user "ISO file '$iso_filename' already exists. Validating checksum..."
                local actual_checksum
                actual_checksum=$(sha256sum "$iso_filename" | awk '{print $1}')
                if [ "$actual_checksum" == "$expected_checksum" ]; then
                    log_user "Checksum is valid. Skipping download."
                else
                    log_user "WARN: Checksum mismatch. Deleting corrupt file." >&2
                    rm -f "$iso_filename"
                fi
            fi
            if [ ! -f "$iso_filename" ]; then
                log_user "Downloading Ubuntu ISO from $iso_url..."
                wget -c -O "$iso_filename" "$iso_url"
                log_user "Validating checksum of new download..."
                local downloaded_checksum
                downloaded_checksum=$(sha256sum "$iso_filename" | awk '{print $1}')
                if [ "$downloaded_checksum" != "$expected_checksum" ]; then
                    error_exit_user "ERROR: Downloaded file checksum does not match expected checksum."
                fi
                log_user "Validation PASSED: Downloaded file checksum is correct."
            fi
            log_user "Creating/updating JSON metadata file '$json_filename'..."
            jq -n \
              --arg url "file:///home/$USER/$iso_filename" \
              --arg checksum "$expected_checksum" \
              --arg type "sha256" \
              '{iso_url: $url, iso_checksum: $checksum, iso_checksum_type: $type}' > "$json_filename"
            log_user "--- Finished Step 5 ---"
        }

        # --- Main execution block ---
        run_step_3
        run_step_4

        if [ "$iso_download_flag" = "true" ]; then
            run_step_5
        else
            log_user "DOWNLOAD_ISO flag is not set to 'true'. Skipping Step 5 (ISO Download)."
        fi
EOF

    if [ $? -ne 0 ]; then
        error_exit "A command running as '$BUILDER_USERNAME' failed. Check output above."
    fi
    log "Finished all user-scoped setup steps successfully."
}

# --- Main Execution ---
main() {
    if [[ $EUID -ne 0 ]]; then
      log "This script must be run as root or with sudo."
      exit 1
    fi

    log "Starting EKS Anywhere image builder setup for RHEL 9.x..."
    configure_ssh
    log "--------------------------------------------------"
    create_builder_user
    log "--------------------------------------------------"
    run_user_scope_steps
    log "--------------------------------------------------"
    log "Setup script completed successfully."
}

main