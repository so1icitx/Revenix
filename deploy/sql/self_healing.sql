-- ============================================================================
-- SELF-HEALING SYSTEM DATABASE SCHEMA
-- Phase 1, Week 1: Persistent Self-Healing State
-- ============================================================================

-- ============================================================================
-- TRUSTED IPS TABLE
-- Tracks IPs that have proven to be trustworthy over time
-- ============================================================================
CREATE TABLE IF NOT EXISTS trusted_ips (
    ip TEXT PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_verified TIMESTAMP NOT NULL DEFAULT NOW(),
    good_flows INTEGER DEFAULT 0 CHECK (good_flows >= 0),
    total_flows INTEGER DEFAULT 0 CHECK (total_flows >= 0),
    avg_risk_score FLOAT DEFAULT 0.0 CHECK (avg_risk_score >= 0.0 AND avg_risk_score <= 1.0),
    auto_added BOOLEAN DEFAULT TRUE,
    confidence FLOAT DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    destinations_count INTEGER DEFAULT 0 CHECK (destinations_count >= 0),
    last_seen TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for trusted IPs
CREATE INDEX IF NOT EXISTS idx_trusted_ips_confidence ON trusted_ips(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_trusted_ips_last_seen ON trusted_ips(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_trusted_ips_auto_added ON trusted_ips(auto_added) WHERE auto_added = TRUE;

COMMENT ON TABLE trusted_ips IS 'Automatically whitelisted IPs based on good behavior patterns';
COMMENT ON COLUMN trusted_ips.confidence IS 'Confidence score 0.0-1.0, decays over time';
COMMENT ON COLUMN trusted_ips.metadata IS 'JSON field for additional context (country, ASN, etc)';

-- ============================================================================
-- BLOCKED IPS TABLE  
-- Tracks IPs that are currently blocked by the firewall
-- ============================================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    block_reason TEXT NOT NULL,
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    alert_count INTEGER DEFAULT 1 CHECK (alert_count > 0),
    manual_override BOOLEAN DEFAULT FALSE,
    threat_category TEXT,
    auto_blocked BOOLEAN DEFAULT TRUE,
    unblock_requested BOOLEAN DEFAULT FALSE,
    unblock_requested_at TIMESTAMP,
    unblock_requested_by TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for blocked IPs
CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_at ON blocked_ips(blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_category ON blocked_ips(threat_category);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(expires_at);

COMMENT ON TABLE blocked_ips IS 'Currently blocked IPs with expiration times';
COMMENT ON COLUMN blocked_ips.expires_at IS 'When the block automatically expires';
COMMENT ON COLUMN blocked_ips.manual_override IS 'True if manually blocked (never auto-expires)';

-- ============================================================================
-- BLOCK HISTORY TABLE
-- Tracks historical block/unblock events for learning
-- ============================================================================
CREATE TABLE IF NOT EXISTS block_history (
    id BIGSERIAL PRIMARY KEY,
    ip TEXT NOT NULL,
    blocked_at TIMESTAMP NOT NULL,
    unblocked_at TIMESTAMP,
    duration_seconds INTEGER,
    reason TEXT NOT NULL,
    was_effective BOOLEAN,
    false_positive BOOLEAN DEFAULT FALSE,
    threat_category TEXT,
    alert_ids INTEGER[],
    feedback_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for block history
CREATE INDEX IF NOT EXISTS idx_block_history_ip ON block_history(ip);
CREATE INDEX IF NOT EXISTS idx_block_history_blocked_at ON block_history(blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_block_history_false_positive ON block_history(false_positive) WHERE false_positive = TRUE;

COMMENT ON TABLE block_history IS 'Historical record of all blocks for analysis and learning';
COMMENT ON COLUMN block_history.was_effective IS 'Did blocking this IP prevent further threats?';
COMMENT ON COLUMN block_history.false_positive IS 'Was this block a mistake?';

-- ============================================================================
-- AI FEEDBACK TABLE
-- User feedback on AI decisions for continuous learning
-- ============================================================================
CREATE TABLE IF NOT EXISTS ai_feedback (
    id BIGSERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    rule_id INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    feedback_type TEXT NOT NULL CHECK (feedback_type IN ('false_positive', 'missed_threat', 'correct', 'severity_wrong', 'category_wrong')),
    user_notes TEXT,
    corrected_severity TEXT,
    corrected_category TEXT,
    corrected_by TEXT,
    corrected_at TIMESTAMP DEFAULT NOW(),
    features_at_time JSONB,
    model_version TEXT,
    ip_affected TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for AI feedback
CREATE INDEX IF NOT EXISTS idx_feedback_alert ON ai_feedback(alert_id);
CREATE INDEX IF NOT EXISTS idx_feedback_type ON ai_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_feedback_ip ON ai_feedback(ip_affected);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON ai_feedback(corrected_at DESC);

COMMENT ON TABLE ai_feedback IS 'User feedback on AI decisions for model improvement';
COMMENT ON COLUMN ai_feedback.features_at_time IS 'Snapshot of features that led to decision';

-- ============================================================================
-- FEATURE FEEDBACK TABLE
-- Tracks which features cause false positives/negatives
-- ============================================================================
CREATE TABLE IF NOT EXISTS feature_feedback (
    id SERIAL PRIMARY KEY,
    feature_name TEXT NOT NULL UNIQUE,
    false_positive_count INTEGER DEFAULT 0 CHECK (false_positive_count >= 0),
    true_positive_count INTEGER DEFAULT 0 CHECK (true_positive_count >= 0),
    false_negative_count INTEGER DEFAULT 0 CHECK (false_negative_count >= 0),
    last_updated TIMESTAMP DEFAULT NOW(),
    importance_score FLOAT DEFAULT 1.0 CHECK (importance_score >= 0.0),
    enabled BOOLEAN DEFAULT TRUE,
    notes TEXT
);

-- Index for feature feedback
CREATE INDEX IF NOT EXISTS idx_feature_importance ON feature_feedback(importance_score DESC);

COMMENT ON TABLE feature_feedback IS 'Track feature effectiveness for model optimization';
COMMENT ON COLUMN feature_feedback.importance_score IS 'Calculated importance, 0.0 = useless, 1.0 = critical';

-- ============================================================================
-- RULE EFFECTIVENESS TABLE
-- Track how well each firewall rule performs
-- ============================================================================
CREATE TABLE IF NOT EXISTS rule_effectiveness (
    rule_id INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
    times_triggered INTEGER DEFAULT 0 CHECK (times_triggered >= 0),
    successful_blocks INTEGER DEFAULT 0 CHECK (successful_blocks >= 0),
    false_blocks INTEGER DEFAULT 0 CHECK (false_blocks >= 0),
    last_triggered TIMESTAMP,
    effectiveness_score FLOAT DEFAULT 0.5 CHECK (effectiveness_score >= 0.0 AND effectiveness_score <= 1.0),
    status TEXT DEFAULT 'testing' CHECK (status IN ('testing', 'active', 'proven', 'deprecated', 'archived')),
    a_b_test_group TEXT CHECK (a_b_test_group IN ('control', 'treatment', NULL)),
    a_b_test_active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for rule effectiveness
CREATE INDEX IF NOT EXISTS idx_rule_effectiveness_score ON rule_effectiveness(effectiveness_score DESC);
CREATE INDEX IF NOT EXISTS idx_rule_effectiveness_status ON rule_effectiveness(status);
CREATE INDEX IF NOT EXISTS idx_rule_effectiveness_ab ON rule_effectiveness(a_b_test_group) WHERE a_b_test_active = TRUE;

COMMENT ON TABLE rule_effectiveness IS 'Track and evaluate firewall rule performance';
COMMENT ON COLUMN rule_effectiveness.effectiveness_score IS 'Score = (successful - false) / total, range 0.0-1.0';

-- ============================================================================
-- RULE TRIGGER LOG TABLE
-- Detailed log of every rule trigger
-- ============================================================================
CREATE TABLE IF NOT EXISTS rule_trigger_log (
    id BIGSERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES rules(id) ON DELETE CASCADE,
    flow_id TEXT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    triggered_at TIMESTAMP DEFAULT NOW(),
    outcome TEXT CHECK (outcome IN ('blocked', 'allowed', 'false_positive', 'rate_limited')),
    feedback_received BOOLEAN DEFAULT FALSE,
    ip_affected TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for rule trigger log
CREATE INDEX IF NOT EXISTS idx_rule_trigger_rule ON rule_trigger_log(rule_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_rule_trigger_outcome ON rule_trigger_log(outcome);
CREATE INDEX IF NOT EXISTS idx_rule_trigger_time ON rule_trigger_log(triggered_at DESC);

COMMENT ON TABLE rule_trigger_log IS 'Audit log of every rule trigger for analysis';

-- ============================================================================
-- MODEL VERSIONS TABLE
-- Track ML model versions and their performance
-- ============================================================================
CREATE TABLE IF NOT EXISTS model_versions (
    version_id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT NOW(),
    model_type TEXT NOT NULL CHECK (model_type IN ('isolation_forest', 'autoencoder', 'device_profiler', 'ensemble', 'lstm', 'other')),
    hyperparameters JSONB NOT NULL,
    training_samples INTEGER CHECK (training_samples > 0),
    validation_accuracy FLOAT CHECK (validation_accuracy >= 0.0 AND validation_accuracy <= 1.0),
    false_positive_rate FLOAT CHECK (false_positive_rate >= 0.0 AND false_positive_rate <= 1.0),
    false_negative_rate FLOAT CHECK (false_negative_rate >= 0.0 AND false_negative_rate <= 1.0),
    f1_score FLOAT CHECK (f1_score >= 0.0 AND f1_score <= 1.0),
    is_active BOOLEAN DEFAULT FALSE,
    file_path TEXT,
    file_size_bytes BIGINT,
    notes TEXT,
    replaced_by TEXT REFERENCES model_versions(version_id) ON DELETE SET NULL,
    deprecated_at TIMESTAMP
);

-- Indexes for model versions
CREATE INDEX IF NOT EXISTS idx_model_versions_active ON model_versions(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_model_versions_type ON model_versions(model_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_versions_performance ON model_versions(f1_score DESC, false_positive_rate ASC);

COMMENT ON TABLE model_versions IS 'Version control and performance tracking for ML models';
COMMENT ON COLUMN model_versions.is_active IS 'Only one version per model_type should be active';

-- ============================================================================
-- MODEL CONFIG TABLE
-- Dynamic configuration for ML models
-- ============================================================================
CREATE TABLE IF NOT EXISTS model_config (
    id SERIAL PRIMARY KEY,
    config_key TEXT UNIQUE NOT NULL,
    config_value TEXT NOT NULL,
    config_type TEXT DEFAULT 'string' CHECK (config_type IN ('string', 'float', 'integer', 'boolean', 'json')),
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by TEXT,
    previous_value TEXT,
    CONSTRAINT config_key_format CHECK (config_key ~ '^[a-z][a-z0-9_]*$')
);

-- Index for model config
CREATE INDEX IF NOT EXISTS idx_model_config_key ON model_config(config_key);

COMMENT ON TABLE model_config IS 'Dynamic configuration for adaptive ML parameters';

-- Insert default configurations
INSERT INTO model_config (config_key, config_value, config_type, description, updated_by) VALUES
    ('contamination_rate_global', '0.01', 'float', 'Global contamination rate for Isolation Forest (1%)', 'system'),
    ('contamination_rate_servers', '0.005', 'float', 'Contamination rate for server devices (0.5%)', 'system'),
    ('contamination_rate_iot', '0.02', 'float', 'Contamination rate for IoT devices (2%)', 'system'),
    ('contamination_rate_workstations', '0.015', 'float', 'Contamination rate for workstations (1.5%)', 'system'),
    ('alert_threshold', '0.85', 'float', 'Minimum risk score to create alert', 'system'),
    ('training_threshold', '200', 'integer', 'Flows required before training ML models', 'system'),
    ('auto_block_threshold', '0.95', 'float', 'Immediate block confidence threshold', 'system'),
    ('suspicious_threshold', '0.75', 'float', 'Confidence threshold to start suspicious tracking', 'system'),
    ('auto_block_enabled', 'true', 'boolean', 'Whether auto-blocking is enabled', 'system'),
    ('confidence_decay_rate', '0.05', 'float', 'Confidence decay per day (5%)', 'system'),
    ('block_duration_minutes', '60', 'integer', 'Default block duration for temporary blocks (minutes)', 'system'),
    ('block_duration_hours', '24', 'integer', 'Legacy block duration in hours', 'system'),
    ('trust_threshold_days', '7', 'integer', 'Days of good behavior required for trust', 'system'),
    ('min_good_flows_for_trust', '100', 'integer', 'Minimum good flows to be trusted', 'system'),
    ('max_flows_stored', '5000', 'integer', 'Maximum number of flows in Redis stream (increased for burst handling)', 'system')
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================================
-- DEVICE BASELINES TABLE
-- Behavioral baselines per device for anomaly detection
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_baselines (
    hostname TEXT PRIMARY KEY,
    typical_hours JSONB NOT NULL DEFAULT '{}'::jsonb,
    typical_ports JSONB NOT NULL DEFAULT '{}'::jsonb,
    typical_protocols JSONB NOT NULL DEFAULT '{}'::jsonb,
    typical_destinations JSONB NOT NULL DEFAULT '{}'::jsonb,
    avg_daily_bytes BIGINT DEFAULT 0 CHECK (avg_daily_bytes >= 0),
    avg_daily_flows INTEGER DEFAULT 0 CHECK (avg_daily_flows >= 0),
    avg_packets_per_flow FLOAT DEFAULT 0.0 CHECK (avg_packets_per_flow >= 0.0),
    avg_bytes_per_packet FLOAT DEFAULT 0.0 CHECK (avg_bytes_per_packet >= 0.0),
    typical_destinations_count INTEGER DEFAULT 0 CHECK (typical_destinations_count >= 0),
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),
    sample_size INTEGER DEFAULT 0 CHECK (sample_size >= 0),
    device_type TEXT CHECK (device_type IN ('server', 'workstation', 'iot', 'mobile', 'unknown')),
    confidence FLOAT DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

-- Indexes for device baselines
CREATE INDEX IF NOT EXISTS idx_device_baselines_updated ON device_baselines(last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_device_baselines_type ON device_baselines(device_type);
CREATE INDEX IF NOT EXISTS idx_device_baselines_confidence ON device_baselines(confidence DESC);

COMMENT ON TABLE device_baselines IS 'Learned behavioral patterns per device for anomaly detection';
COMMENT ON COLUMN device_baselines.typical_hours IS 'JSON: {0: 50, 1: 20, ...} packets per hour of day';
COMMENT ON COLUMN device_baselines.typical_ports IS 'JSON: {443: 0.6, 80: 0.3} port usage frequency';

-- ============================================================================
-- INCIDENTS TABLE
-- Link related alerts into attack chains
-- ============================================================================
CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP,
    source_ip TEXT NOT NULL,
    target_device TEXT NOT NULL,
    attack_stages JSONB DEFAULT '[]'::jsonb,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    alert_ids INTEGER[] NOT NULL,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'investigating', 'resolved', 'false_positive')),
    auto_generated BOOLEAN DEFAULT TRUE,
    assigned_to TEXT,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for incidents
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(started_at DESC);

COMMENT ON TABLE incidents IS 'Multi-stage attack incidents reconstructed from related alerts';
COMMENT ON COLUMN incidents.attack_stages IS 'JSON array: ["reconnaissance", "exploitation", "lateral_movement"]';

-- ============================================================================
-- FIREWALL SYNC LOG TABLE
-- Track synchronization between database and actual firewall
-- ============================================================================
CREATE TABLE IF NOT EXISTS firewall_sync_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT NOW(),
    action TEXT NOT NULL CHECK (action IN ('block', 'unblock', 'sync_full')),
    ip TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    execution_time_ms INTEGER
);

-- Indexes for firewall sync log
CREATE INDEX IF NOT EXISTS idx_firewall_sync_time ON firewall_sync_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_firewall_sync_failures ON firewall_sync_log(success) WHERE success = FALSE;

COMMENT ON TABLE firewall_sync_log IS 'Audit log of firewall rule synchronization';

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to calculate rule effectiveness score
CREATE OR REPLACE FUNCTION calculate_rule_effectiveness(rule_id_param INTEGER)
RETURNS FLOAT AS $$
DECLARE
    effectiveness FLOAT;
    total INT;
    successful INT;
    false_pos INT;
BEGIN
    SELECT times_triggered, successful_blocks, false_blocks
    INTO total, successful, false_pos
    FROM rule_effectiveness
    WHERE rule_id = rule_id_param;
    
    IF total = 0 THEN
        RETURN 0.5; -- Default score for new rules
    END IF;
    
    -- Score = (successful - false_positives) / total
    effectiveness := (successful - false_pos)::FLOAT / total::FLOAT;
    
    -- Clamp to 0.0-1.0 range
    RETURN GREATEST(0.0, LEAST(1.0, effectiveness));
END;
$$ LANGUAGE plpgsql;

-- Function to auto-archive old block history
CREATE OR REPLACE FUNCTION archive_old_block_history()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM block_history
    WHERE blocked_at < NOW() - INTERVAL '180 days'
    RETURNING COUNT(*) INTO deleted_count;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger to update timestamps
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update_timestamp trigger to relevant tables
CREATE TRIGGER trigger_trusted_ips_updated
    BEFORE UPDATE ON trusted_ips
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_blocked_ips_updated
    BEFORE UPDATE ON blocked_ips
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_rule_effectiveness_updated
    BEFORE UPDATE ON rule_effectiveness
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_device_baselines_updated
    BEFORE UPDATE ON device_baselines
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trigger_incidents_updated
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- ============================================================================
-- VIEWS FOR CONVENIENCE
-- ============================================================================

-- View: Active blocks with time remaining
CREATE OR REPLACE VIEW active_blocks AS
SELECT 
    ip,
    blocked_at,
    expires_at,
    EXTRACT(EPOCH FROM (expires_at - NOW()))/3600 AS hours_remaining,
    block_reason,
    confidence,
    threat_category,
    alert_count
FROM blocked_ips
WHERE expires_at > NOW()
ORDER BY expires_at DESC;

-- View: Rule performance summary
CREATE OR REPLACE VIEW rule_performance AS
SELECT 
    r.id,
    r.action,
    r.target,
    re.times_triggered,
    re.successful_blocks,
    re.false_blocks,
    re.effectiveness_score,
    re.status,
    re.last_triggered
FROM rules r
LEFT JOIN rule_effectiveness re ON r.id = re.rule_id
ORDER BY re.effectiveness_score DESC NULLS LAST;

-- View: Incident summary
CREATE OR REPLACE VIEW incident_summary AS
SELECT 
    i.id,
    i.started_at,
    i.source_ip,
    i.target_device,
    i.severity,
    i.status,
    cardinality(i.alert_ids) as alert_count,
    jsonb_array_length(i.attack_stages) as stage_count
FROM incidents i
WHERE i.status IN ('active', 'investigating')
ORDER BY i.started_at DESC;

COMMENT ON VIEW active_blocks IS 'Currently active IP blocks with time remaining';
COMMENT ON VIEW rule_performance IS 'Performance summary for all firewall rules';
COMMENT ON VIEW incident_summary IS 'Summary of active security incidents';
