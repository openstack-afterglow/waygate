packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "agent_dir" { type = string }
variable "agent_version" { type = string }
variable "agent_sha256" { type = string }
variable "base_image_url" {
  type    = string
  default = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}
variable "base_image_checksum" {
  type    = string
  default = "file:https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
}
variable "accelerator" {
  type    = string
  default = "kvm"
}
variable "cpu_model" {
  type    = string
  default = "host"
}
variable "qemu_binary" {
  type    = string
  default = "qemu-system-x86_64"
}
variable "output_directory" {
  type    = string
  default = "output"
}
variable "disk_size" {
  type    = string
  default = "4G"
}
variable "memory" {
  type    = number
  default = 2048
}
variable "cpus" {
  type    = number
  default = 2
}
variable "headless" {
  type    = bool
  default = true
}

local "ssh_password" {
  sensitive  = true
  expression = uuidv4()
}
locals {
  vm_name = "waygate-gateway-${var.agent_version}-ubuntu-24.04-amd64.qcow2"
}

source "qemu" "gateway" {
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_image       = true
  format           = "qcow2"
  accelerator      = var.accelerator
  cpu_model        = var.cpu_model
  qemu_binary      = var.qemu_binary
  headless         = var.headless
  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  net_device       = "virtio-net"
  disk_interface   = "virtio"
  cd_label         = "cidata"
  cd_content = {
    "meta-data" = "instance-id: waygate-packer\nlocal-hostname: waygate-packer\n"
    "user-data" = "#cloud-config\n${yamlencode({
      users = [{
        name              = "packer"
        sudo              = "ALL=(ALL) NOPASSWD:ALL"
        shell             = "/bin/bash"
        lock_passwd       = false
        plain_text_passwd = local.ssh_password
      }]
      ssh_pwauth = true
    })}"
  }
  ssh_username     = "packer"
  ssh_password     = local.ssh_password
  ssh_timeout      = "20m"
  shutdown_command = "sudo sh -c 'userdel -f -r packer; shutdown -P now'"
  output_directory = var.output_directory
  vm_name          = local.vm_name
}

build {
  sources = ["source.qemu.gateway"]
  provisioner "shell" {
    inline = ["mkdir -p /tmp/waygate-agent"]
  }
  provisioner "file" {
    source      = "${var.agent_dir}/"
    destination = "/tmp/waygate-agent"
  }
  provisioner "shell" {
    script = "${path.root}/provision.sh"
    environment_vars = [
      "AGENT_VERSION=${var.agent_version}",
      "AGENT_SHA256=${var.agent_sha256}",
    ]
    use_env_var_file = true
    execute_command = "chmod +x {{ .Path }}; sudo /bin/bash -c '. {{ .EnvVarFile }}; {{ .Path }}'"
  }
  post-processor "checksum" {
    checksum_types = ["sha256"]
    output         = "${var.output_directory}/${local.vm_name}.sha256"
  }
  post-processor "manifest" {
    output = "${var.output_directory}/manifest.json"
  }
}
