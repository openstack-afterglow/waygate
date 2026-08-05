CREATE TABLE IF NOT EXISTS waygate_servers (
  id CHAR(36) NOT NULL,
  project_id VARCHAR(64) NOT NULL,
  name VARCHAR(63) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'CREATING',
  status_reason TEXT NULL,
  server_vm_id VARCHAR(64) NULL,
  flavor_id VARCHAR(64) NULL,
  image_id VARCHAR(128) NULL,
  provider_network_id VARCHAR(64) NULL,
  floating_network_id VARCHAR(128) NULL,
  resource_policy_snapshot JSON NULL,
  provider_port_id VARCHAR(64) NULL,
  security_group_id VARCHAR(64) NULL,
  fip_id VARCHAR(64) NULL,
  endpoint_ip VARCHAR(45) NULL,
  key_name VARCHAR(255) NULL,
  agent_token_encrypted TEXT NULL,
  server_public_key VARCHAR(64) NULL,
  listen_port INT NOT NULL DEFAULT 51820,
  tunnel_cidr VARCHAR(43) NOT NULL DEFAULT '10.8.0.0/24',
  dns VARCHAR(255) NULL,
  mtu INT NULL,
  created_by_user_id VARCHAR(64) NULL,
  created_by_username VARCHAR(255) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  deleted_at DATETIME(6) NULL,
  deleted_by_user_id VARCHAR(64) NULL,
  deleted_reason VARCHAR(255) NULL,
  PRIMARY KEY (id),
  KEY idx_waygate_server_project_created (project_id, created_at),
  KEY ix_waygate_servers_project_id (project_id),
  KEY ix_waygate_servers_created_by_user_id (created_by_user_id),
  KEY ix_waygate_servers_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS waygate_clients (
  id CHAR(36) NOT NULL,
  server_id CHAR(36) NOT NULL,
  project_id VARCHAR(64) NOT NULL,
  name VARCHAR(63) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  public_key VARCHAR(64) NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  preshared_key_encrypted TEXT NULL,
  tunnel_ip VARCHAR(45) NULL,
  allowed_ips JSON NULL,
  dns VARCHAR(255) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  deleted_at DATETIME(6) NULL,
  deleted_by_user_id VARCHAR(64) NULL,
  deleted_reason VARCHAR(255) NULL,
  PRIMARY KEY (id),
  CONSTRAINT uq_waygate_client_server_tunnel_ip UNIQUE (server_id, tunnel_ip),
  CONSTRAINT uq_waygate_client_server_name UNIQUE (server_id, name),
  CONSTRAINT fk_waygate_clients_server FOREIGN KEY (server_id) REFERENCES waygate_servers(id) ON DELETE CASCADE,
  KEY idx_waygate_client_project_created (project_id, created_at),
  KEY ix_waygate_clients_server_id (server_id),
  KEY ix_waygate_clients_project_id (project_id),
  KEY ix_waygate_clients_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS waygate_network_attachments (
  id INT NOT NULL AUTO_INCREMENT,
  server_id CHAR(36) NOT NULL,
  project_id VARCHAR(64) NOT NULL,
  network_id VARCHAR(64) NOT NULL,
  subnet_id VARCHAR(64) NULL,
  port_id VARCHAR(64) NULL,
  cidr VARCHAR(43) NULL,
  nat_mode VARCHAR(16) NOT NULL DEFAULT 'snat',
  status VARCHAR(20) NOT NULL DEFAULT 'CREATING',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT fk_waygate_network_attachments_server FOREIGN KEY (server_id) REFERENCES waygate_servers(id) ON DELETE CASCADE,
  KEY idx_waygate_netattach_server (server_id),
  KEY ix_waygate_network_attachments_project_id (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS waygate_jobs (
  id CHAR(36) NOT NULL PRIMARY KEY,
  server_id CHAR(36) NOT NULL,
  project_id VARCHAR(64) NOT NULL,
  kind VARCHAR(16) NOT NULL,
  status VARCHAR(16) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  last_error TEXT NULL,
  user_id VARCHAR(64) NULL,
  username VARCHAR(255) NULL,
  claimed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  KEY idx_waygate_jobs_claim (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS resource_policies (
  policy_key VARCHAR(100) NOT NULL,
  resource_kind VARCHAR(32) NOT NULL,
  resource_id VARCHAR(128) NULL,
  resource_name VARCHAR(255) NULL,
  constraints JSON NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (policy_key),
  KEY idx_resource_policies_kind (resource_kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO resource_policies
  (policy_key, resource_kind, resource_id, resource_name, constraints, updated_by_user_id, created_at, updated_at)
VALUES
  ('waygate.provider_network', 'network', NULL, NULL, JSON_OBJECT('shared_only', TRUE), NULL, NOW(6), NOW(6)),
  ('waygate.image', 'image', NULL, NULL, JSON_OBJECT(), NULL, NOW(6), NOW(6)),
  ('waygate.flavor', 'flavor', NULL, NULL, JSON_OBJECT(), NULL, NOW(6), NOW(6)),
  ('waygate.floating_network', 'network', NULL, NULL, JSON_OBJECT('external_only', TRUE), NULL, NOW(6), NOW(6));
