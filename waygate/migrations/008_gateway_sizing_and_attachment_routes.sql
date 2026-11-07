-- Gateway sizing: requested client count and the applied flavor tier (NULL for older servers).
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS expected_clients INT NULL;
ALTER TABLE waygate_servers ADD COLUMN IF NOT EXISTS flavor_tier VARCHAR(16) NULL;
-- Client routes become a per-attachment setting, separate from the physical NAT CIDR.
ALTER TABLE waygate_network_attachments ADD COLUMN IF NOT EXISTS allowed_ips JSON NULL;
-- Preserve current client routing exactly: every existing attachment advertises its own CIDR.
UPDATE waygate_network_attachments SET allowed_ips = JSON_ARRAY(cidr) WHERE allowed_ips IS NULL AND cidr IS NOT NULL;
UPDATE waygate_network_attachments SET allowed_ips = JSON_ARRAY() WHERE allowed_ips IS NULL;
