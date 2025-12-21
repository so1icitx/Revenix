-- Migration: Add firewall sync log table
-- Version: 003

-- Create firewall_sync_log table if not exists
CREATE TABLE IF NOT EXISTS firewall_sync_log (
    id SERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    ip TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    execution_time_ms INTEGER DEFAULT 0,
    platform TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_firewall_sync_log_ip ON firewall_sync_log(ip);
CREATE INDEX IF NOT EXISTS idx_firewall_sync_log_created ON firewall_sync_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_firewall_sync_log_success ON firewall_sync_log(success);

COMMENT ON TABLE firewall_sync_log IS 'Log of firewall sync actions for auditing and debugging';
