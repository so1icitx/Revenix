-- Add threat_category column to alerts table
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_category VARCHAR(50);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_alerts_threat_category ON alerts(threat_category);
