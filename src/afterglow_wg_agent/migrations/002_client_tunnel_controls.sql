ALTER TABLE clients ADD COLUMN mtu INTEGER NOT NULL DEFAULT 1420 CHECK(mtu >= 1280 AND mtu <= 1500);
ALTER TABLE clients ADD COLUMN persistent_keepalive INTEGER NOT NULL DEFAULT 25 CHECK(persistent_keepalive >= 0 AND persistent_keepalive <= 65535);
