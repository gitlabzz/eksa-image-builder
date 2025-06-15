terraform {
  required_providers {
    vagrant = {
      source  = "bmatcuk/vagrant"
      version = "~> 4.0"
    }
  }
}

# Watch the Vagrantfile so Terraform re-provisions when it changes
data "local_file" "vagrantfile_checksum" {
  filename = "${path.module}/Vagrantfile"
}

resource "null_resource" "vagrant_reload" {
  triggers = {
    vagrantfile_sha256 = data.local_file.vagrantfile_checksum.content_sha256
  }

  provisioner "local-exec" {
    command = "vagrant reload || true"
  }
}

resource "vagrant_vm" "eks_admin_vm" {
  name            = "eks-image-builder"
  vagrantfile_dir = path.module

  # Pass VAGRANT_LOG=info to surface early errors in CI
  env = {
    VAGRANT_LOG = "info"
  }

  depends_on = [null_resource.vagrant_reload]
}

# Handy outputs
output "ssh_commands" {
  value = vagrant_vm.eks_admin_vm.ssh_config[*].command
}

output "ssh_command" {
  value = join("", vagrant_vm.eks_admin_vm.ssh_config[*].command)
}
