ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS agent_install_mode VARCHAR(16) NOT NULL DEFAULT 'cloud-init';
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS agent_token_next_encrypted TEXT NULL;
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS agent_token_issued_at DATETIME(6) NULL;
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS agent_token_rotation_requested_at DATETIME(6) NULL;
