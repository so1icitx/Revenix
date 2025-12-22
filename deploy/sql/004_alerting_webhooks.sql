-- Alerting webhooks configuration
CREATE TABLE IF NOT EXISTS alerting_webhooks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'webhook', -- slack, discord, email, webhook, pagerduty
    enabled BOOLEAN DEFAULT TRUE,
    events JSONB DEFAULT '["critical", "high"]',
    headers JSONB DEFAULT '{}',
    last_triggered_at TIMESTAMP,
    trigger_count INTEGER DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Index for quick lookup of enabled webhooks
CREATE INDEX IF NOT EXISTS idx_alerting_webhooks_enabled ON alerting_webhooks(enabled) WHERE enabled = TRUE;

-- Alert notification log
CREATE TABLE IF NOT EXISTS alert_notifications (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    webhook_id INTEGER REFERENCES alerting_webhooks(id),
    status VARCHAR(20) NOT NULL, -- sent, failed, pending
    response_code INTEGER,
    error_message TEXT,
    sent_at TIMESTAMP DEFAULT NOW()
);

-- Index for notification history
CREATE INDEX IF NOT EXISTS idx_alert_notifications_alert ON alert_notifications(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_notifications_sent ON alert_notifications(sent_at DESC);
