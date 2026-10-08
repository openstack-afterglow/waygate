-- Unknown legacy owners remain unassigned; never infer ownership from project or creator.
ALTER TABLE waygate_clients ADD COLUMN IF NOT EXISTS owner_user_id VARCHAR(64) NULL;
