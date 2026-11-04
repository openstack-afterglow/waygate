-- Apply before new API/worker processes; old writers remain caller_trust.
-- Drain/replace old workers before enabling dedicated admin execution.
ALTER TABLE waygate_execution_grants
  ADD COLUMN IF NOT EXISTS execution_mode VARCHAR(32) NOT NULL DEFAULT 'caller_trust';
ALTER TABLE waygate_execution_grants
  ADD COLUMN IF NOT EXISTS executor_user_id VARCHAR(64) NULL;
