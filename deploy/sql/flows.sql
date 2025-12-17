CREATE TABLE flows (
    id SERIAL PRIMARY KEY,
    flow_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    bytes BIGINT NOT NULL,
    packets BIGINT NOT NULL,
    start_ts BIGINT NOT NULL,
    end_ts BIGINT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Day 22: Training data safety flags
    verified_benign BOOLEAN DEFAULT NULL,
    analyzed_at TIMESTAMP DEFAULT NULL,
    analysis_version INTEGER DEFAULT 1,
    training_excluded BOOLEAN DEFAULT FALSE,
    -- Day 23: Flow aggregation and deduplication
    flow_count INTEGER DEFAULT 1,  -- Number of identical flows aggregated
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Last time this flow pattern was seen
);

-- Simplified deduplication index using 5-second bucketed start_ts
CREATE UNIQUE INDEX IF NOT EXISTS idx_flows_dedup
ON flows(src_ip, dst_ip, src_port, dst_port, protocol, (start_ts - (start_ts % 5)));

-- Training data query indexes
CREATE INDEX IF NOT EXISTS idx_flows_verified_benign ON flows(verified_benign) WHERE verified_benign = TRUE;
CREATE INDEX IF NOT EXISTS idx_flows_training_safe ON flows(timestamp, training_excluded) WHERE training_excluded = FALSE;
CREATE INDEX IF NOT EXISTS idx_flows_analyzed ON flows(analyzed_at) WHERE analyzed_at IS NULL;

-- Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_device_time ON flows(hostname, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_flows_aggregation ON flows(src_ip, dst_ip, protocol, timestamp DESC);
UPDATE flows SET flow_count = 1 WHERE flow_count IS NULL;
