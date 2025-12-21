-- Migration: Add permanent IP support and improve blocking
-- Version: 002

-- Add permanent flag to trusted_ips
ALTER TABLE trusted_ips ADD COLUMN IF NOT EXISTS permanent BOOLEAN DEFAULT FALSE;
ALTER TABLE trusted_ips ADD COLUMN IF NOT EXISTS added_by TEXT DEFAULT 'system';
ALTER TABLE trusted_ips ADD COLUMN IF NOT EXISTS notes TEXT;

-- Add permanent flag to blocked_ips  
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS permanent BOOLEAN DEFAULT FALSE;
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS added_by TEXT DEFAULT 'system';
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS notes TEXT;

-- Create index for permanent IPs
CREATE INDEX IF NOT EXISTS idx_trusted_ips_permanent ON trusted_ips(permanent) WHERE permanent = TRUE;
CREATE INDEX IF NOT EXISTS idx_blocked_ips_permanent ON blocked_ips(permanent) WHERE permanent = TRUE;

-- Update comments
COMMENT ON COLUMN trusted_ips.permanent IS 'If TRUE, IP is permanently whitelisted and never expires';
COMMENT ON COLUMN blocked_ips.permanent IS 'If TRUE, IP is permanently blocked and never expires';

-- Webhook/alerting configuration
CREATE TABLE IF NOT EXISTS alert_webhooks (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    webhook_type TEXT NOT NULL DEFAULT 'generic',
    enabled BOOLEAN DEFAULT TRUE,
    min_severity TEXT DEFAULT 'medium',
    headers JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Webhook delivery log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id SERIAL PRIMARY KEY,
    webhook_id INTEGER REFERENCES alert_webhooks(id),
    alert_id INTEGER,
    status_code INTEGER,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
