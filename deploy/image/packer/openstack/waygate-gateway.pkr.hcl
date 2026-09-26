packer {
  required_plugins {
    openstack = {
      source  = "github.com/hashicorp/openstack"
      version = ">= 1.1.4"
    }
  }
}

variable "agent_dir" { type = string }
variable "agent_version" { type = string }
variable "agent_sha256" { type = string }
variable "source_image" {
  type        = string
  description = "Glance ID of a stock Ubuntu 24.04 amd64 cloud image."
}
variable "flavor" {
  type        = string
  description = "Build VM flavor ID or name; allow enough root disk for Ubuntu and packages."
}
variable "network_id" {
  type        = string
  description = "Neutron build-network UUID, with package repository access."
}
variable "security_groups" {
  type        = list(string)
  default     = ["default"]
  description = "Existing security group names allowing SSH from the Packer runner."
}
variable "floating_ip_network" {
  type        = string
  default     = ""
  description = "Optional external network ID/name for a temporary floating IP."
}
variable "ssh_username" {
  type    = string
  default = "ubuntu"
}
variable "availability_zone" {
  type    = string
  default = ""
}
variable "image_name" {
  type    = string
  default = ""
}
variable "image_visibility" {
  type    = string
  default = "public"
  validation {
    condition     = contains(["public", "community"], var.image_visibility)
    error_message = "Waygate image policies require public or community visibility."
  }
}
variable "output_directory" {
  type    = string
  default = "output"
}

source "openstack" "gateway" {
  # Authentication comes from OS_CLOUD/clouds.yaml or standard OS_* variables.
  source_image             = var.source_image
  flavor                   = var.flavor
  networks                 = [var.network_id]
  security_groups          = var.security_groups
  availability_zone        = var.availability_zone
  floating_ip_network      = var.floating_ip_network
  instance_floating_ip_net  = var.network_id
  ssh_ip_version           = "4"
  ssh_username             = var.ssh_username
  ssh_timeout              = "20m"
  ssh_clear_authorized_keys = true
  image_name               = var.image_name != "" ? var.image_name : "waygate-gateway:${var.agent_version}-ubuntu-24.04"
  image_visibility         = var.image_visibility
  metadata = {
    waygate_agent         = "prebuilt"
    waygate_agent_version = var.agent_version
    waygate_agent_sha256  = var.agent_sha256
    os_type               = "linux"
    os_distro             = "ubuntu"
  }
}

build {
  sources = ["source.openstack.gateway"]
  provisioner "shell" {
    inline = ["mkdir -p /tmp/waygate-agent"]
  }
  provisioner "file" {
    source      = "${var.agent_dir}/"
    destination = "/tmp/waygate-agent"
  }
  provisioner "shell" {
    script = "${path.root}/../provision.sh"
    environment_vars = [
      "AGENT_VERSION=${var.agent_version}",
      "AGENT_SHA256=${var.agent_sha256}",
    ]
    use_env_var_file = true
    execute_command = "chmod +x {{ .Path }}; sudo /bin/bash -c '. {{ .EnvVarFile }}; {{ .Path }}'"
  }
  post-processor "manifest" {
    output = "${var.output_directory}/manifest.json"
  }
}
