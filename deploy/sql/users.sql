-- ============================================================================
-- USERS & AUTHENTICATION SYSTEM
-- Secure user management with role-based access control
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,  -- bcrypt hashed password
    full_name VARCHAR(255) NOT NULL,
    organization VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'analyst', 'user')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = TRUE;

COMMENT ON TABLE users IS 'System users with authentication and role-based access control';
COMMENT ON COLUMN users.password_hash IS 'bcrypt hashed password (never store plain text!)';
COMMENT ON COLUMN users.role IS 'User role: admin (full access), analyst (read+investigate), user (read only)';
COMMENT ON COLUMN users.failed_login_attempts IS 'Track failed login attempts for account protection';
COMMENT ON COLUMN users.locked_until IS 'Account temporarily locked until this timestamp after too many failed attempts';

-- ============================================================================
-- USER SESSIONS
-- Track active user sessions for security
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,  -- Hashed JWT token for revocation
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);

COMMENT ON TABLE user_sessions IS 'Active user sessions for session management and security';

-- ============================================================================
-- AUDIT LOG
-- Track all important user actions for security auditing
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);

COMMENT ON TABLE audit_log IS 'Security audit log tracking all important user actions';

-- ============================================================================
-- CREATE DEFAULT ADMIN USER (COMMENTED OUT FOR COMPETITION DEMO)
-- Uncomment this if you need a default admin account
-- Password: Admin123! (CHANGE THIS IN PRODUCTION!)
-- ============================================================================

-- Note: This is a bcrypt hash of "Admin123!"
-- In production, admin should change this immediately after first login
-- INSERT INTO users (username, email, password_hash, full_name, role, organization)
-- VALUES (
--     'admin',
--     'admin@revenix.local',
--     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIxFQ3HCvW',  -- Admin123!
--     'System Administrator',
--     'admin',
--     'Revenix Security'
-- )
-- ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions
    WHERE expires_at < NOW() OR (last_activity < NOW() - INTERVAL '7 days');
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update last_activity on session access
CREATE OR REPLACE FUNCTION update_session_activity()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_activity = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECURITY POLICIES
-- ============================================================================

-- Password policy: Never expose password hashes in SELECT queries
CREATE OR REPLACE FUNCTION mask_password() 
RETURNS TRIGGER AS $$
BEGIN
    -- This is just a reminder - actual masking should be done in application layer
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
