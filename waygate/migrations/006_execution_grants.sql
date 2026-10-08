CREATE TABLE IF NOT EXISTS waygate_execution_grants (
  id CHAR(36) NOT NULL PRIMARY KEY,
  project_id VARCHAR(64) NOT NULL,
  server_id CHAR(36) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  capability VARCHAR(64) NOT NULL,
  purpose VARCHAR(16) NOT NULL,
  trust_id VARCHAR(64) NULL,
  trustee_user_id VARCHAR(64) NULL,
  role_id VARCHAR(64) NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'admitting',
  expires_at DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  CONSTRAINT uq_waygate_execution_trust UNIQUE (trust_id),
  KEY idx_waygate_grant_cleanup (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE waygate_jobs
  ADD COLUMN IF NOT EXISTS execution_grant_id CHAR(36) NULL;
ALTER TABLE waygate_jobs
  ADD UNIQUE KEY IF NOT EXISTS uq_waygate_job_execution_grant (execution_grant_id);
ALTER TABLE waygate_jobs
  ADD CONSTRAINT fk_waygate_job_execution_grant FOREIGN KEY IF NOT EXISTS (execution_grant_id)
    REFERENCES waygate_execution_grants(id);
