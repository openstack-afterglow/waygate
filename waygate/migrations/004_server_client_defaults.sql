-- Preserve existing server DNS/MTU and explicit client tunnel settings.
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS persistent_keepalive INT NOT NULL DEFAULT 25;
ALTER TABLE waygate_clients ADD COLUMN IF NOT EXISTS inherit_dns BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE waygate_clients ADD COLUMN IF NOT EXISTS inherit_persistent_keepalive BOOLEAN NOT NULL DEFAULT FALSE;
