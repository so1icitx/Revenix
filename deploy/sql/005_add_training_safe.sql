-- Migration: Add training_safe column to flows table
-- This column tracks whether a flow is safe for ML training

ALTER TABLE flows ADD COLUMN IF NOT EXISTS training_safe BOOLEAN DEFAULT FALSE;

-- Create index for training_safe queries
CREATE INDEX IF NOT EXISTS idx_flows_training_safe_col ON flows(training_safe) WHERE training_safe = TRUE;

-- Set existing verified_benign flows as training_safe
UPDATE flows SET training_safe = TRUE WHERE verified_benign = TRUE;

-- Also add to model_config if not exists
INSERT INTO model_config (config_key, config_value, config_type, description)
VALUES ('learning_phase', 'idle', 'string', 'Current learning phase: idle, learning, active')
ON CONFLICT (config_key) DO NOTHING;
