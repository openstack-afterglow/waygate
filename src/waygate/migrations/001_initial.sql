CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE installation_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    installation_id TEXT NOT NULL UNIQUE,
    wg_interface TEXT NOT NULL,
    wg_config_path TEXT NOT NULL,
    server_network TEXT NOT NULL,
    server_address TEXT NOT NULL,
    server_public_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    name TEXT COLLATE NOCASE NOT NULL UNIQUE,
    address TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    allowed_ips_json TEXT NOT NULL,
    dns_json TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE share_tokens (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    single_use INTEGER NOT NULL CHECK(single_use IN (0, 1)),
    used_at TEXT,
    created_at TEXT NOT NULL
);
