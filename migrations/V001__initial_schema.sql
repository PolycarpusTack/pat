-- V001__initial_schema.sql
-- Initial database schema for Pat platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create custom types
CREATE TYPE email_status AS ENUM ('received', 'processing', 'processed', 'failed', 'deleted');
CREATE TYPE email_protocol AS ENUM ('smtp', 'http', 'graphql', 'websocket', 'grpc');
CREATE TYPE workflow_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE plugin_status AS ENUM ('active', 'inactive', 'error', 'installing', 'uninstalling');

-- Create schemas
CREATE SCHEMA IF NOT EXISTS pat;
CREATE SCHEMA IF NOT EXISTS pat_audit;

-- Set search path
SET search_path TO pat, public;

-- Tenants table (for multi-tenancy)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    limits JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_deleted_at ON tenants(deleted_at);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    settings JSONB DEFAULT '{}',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- Emails table (partitioned by created_at)
CREATE TABLE emails (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    message_id VARCHAR(500) NOT NULL,
    conversation_id UUID,
    
    -- Email metadata
    from_address VARCHAR(500) NOT NULL,
    from_name VARCHAR(500),
    to_addresses JSONB NOT NULL DEFAULT '[]',
    cc_addresses JSONB DEFAULT '[]',
    bcc_addresses JSONB DEFAULT '[]',
    subject TEXT,
    
    -- Content
    text_body TEXT,
    html_body TEXT,
    raw_email TEXT,
    headers JSONB DEFAULT '{}',
    
    -- Attachments
    attachments JSONB DEFAULT '[]',
    attachment_count INTEGER DEFAULT 0,
    total_size_bytes BIGINT DEFAULT 0,
    
    -- Protocol info
    protocol email_protocol NOT NULL,
    source_ip INET,
    source_port INTEGER,
    
    -- Processing info
    status email_status NOT NULL DEFAULT 'received',
    spam_score FLOAT,
    spam_details JSONB,
    virus_scan_result JSONB,
    validation_results JSONB,
    
    -- Timestamps
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    PRIMARY KEY (id, created_at),
    CONSTRAINT fk_emails_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) PARTITION BY RANGE (created_at);

-- Create partitions for the next 12 months
DO $$
DECLARE
    start_date DATE := DATE_TRUNC('month', CURRENT_DATE);
    end_date DATE;
    partition_name TEXT;
BEGIN
    FOR i IN 0..11 LOOP
        end_date := start_date + INTERVAL '1 month';
        partition_name := 'emails_' || TO_CHAR(start_date, 'YYYY_MM');
        
        EXECUTE format('
            CREATE TABLE IF NOT EXISTS %I PARTITION OF emails
            FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        -- Create indexes on partition
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_tenant_id ON %I(tenant_id)', partition_name, partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_message_id ON %I(message_id)', partition_name, partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_from_address ON %I(from_address)', partition_name, partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_status ON %I(status)', partition_name, partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_created_at ON %I(created_at)', partition_name, partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_subject_trgm ON %I USING gin (subject gin_trgm_ops)', partition_name, partition_name);
        
        start_date := end_date;
    END LOOP;
END $$;

-- Workflows table
CREATE TABLE workflows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_rules JSONB NOT NULL DEFAULT '{}',
    steps JSONB NOT NULL DEFAULT '[]',
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_workflows_tenant_id ON workflows(tenant_id);
CREATE INDEX idx_workflows_is_active ON workflows(is_active);
CREATE INDEX idx_workflows_deleted_at ON workflows(deleted_at);

-- Workflow executions table
CREATE TABLE workflow_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    email_id UUID,
    trigger_type VARCHAR(50) NOT NULL,
    status workflow_status NOT NULL DEFAULT 'pending',
    context JSONB DEFAULT '{}',
    result JSONB,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workflow_executions_tenant_id ON workflow_executions(tenant_id);
CREATE INDEX idx_workflow_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX idx_workflow_executions_email_id ON workflow_executions(email_id);
CREATE INDEX idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX idx_workflow_executions_created_at ON workflow_executions(created_at);

-- Plugins table
CREATE TABLE plugins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    description TEXT,
    author VARCHAR(255),
    repository_url VARCHAR(500),
    manifest JSONB NOT NULL,
    config JSONB DEFAULT '{}',
    status plugin_status NOT NULL DEFAULT 'inactive',
    is_global BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(name, version, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::UUID))
);

CREATE INDEX idx_plugins_tenant_id ON plugins(tenant_id);
CREATE INDEX idx_plugins_status ON plugins(status);
CREATE INDEX idx_plugins_is_global ON plugins(is_global);

-- API keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    permissions JSONB DEFAULT '[]',
    rate_limit INTEGER DEFAULT 1000,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at);

-- Webhook endpoints table
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL,
    events JSONB NOT NULL DEFAULT '[]',
    headers JSONB DEFAULT '{}',
    secret VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    failure_count INTEGER DEFAULT 0,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_webhook_endpoints_tenant_id ON webhook_endpoints(tenant_id);
CREATE INDEX idx_webhook_endpoints_is_active ON webhook_endpoints(is_active);

-- Email tags table (many-to-many)
CREATE TABLE email_tags (
    email_id UUID NOT NULL,
    tag VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (email_id, tag)
);

CREATE INDEX idx_email_tags_tag ON email_tags(tag);

-- Audit log table
CREATE TABLE pat_audit.audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    record_id UUID,
    old_data JSONB,
    new_data JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_tenant_id ON pat_audit.audit_log(tenant_id);
CREATE INDEX idx_audit_log_user_id ON pat_audit.audit_log(user_id);
CREATE INDEX idx_audit_log_table_record ON pat_audit.audit_log(table_name, record_id);
CREATE INDEX idx_audit_log_created_at ON pat_audit.audit_log(created_at);

-- Helper functions
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO pat_audit.audit_log (
        tenant_id,
        user_id,
        action,
        table_name,
        record_id,
        old_data,
        new_data
    ) VALUES (
        COALESCE(NEW.tenant_id, OLD.tenant_id),
        current_setting('app.current_user_id', true)::UUID,
        TG_OP,
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update triggers
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_emails_updated_at BEFORE UPDATE ON emails FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON workflows FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_plugins_updated_at BEFORE UPDATE ON plugins FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_webhook_endpoints_updated_at BEFORE UPDATE ON webhook_endpoints FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Apply audit triggers to important tables
CREATE TRIGGER audit_tenants AFTER INSERT OR UPDATE OR DELETE ON tenants FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_users AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_workflows AFTER INSERT OR UPDATE OR DELETE ON workflows FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_plugins AFTER INSERT OR UPDATE OR DELETE ON plugins FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_api_keys AFTER INSERT OR UPDATE OR DELETE ON api_keys FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

-- Row Level Security policies
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE plugins ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;

-- Grant permissions
GRANT USAGE ON SCHEMA pat TO pat_app;
GRANT USAGE ON SCHEMA pat_audit TO pat_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pat TO pat_app;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA pat_audit TO pat_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pat TO pat_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pat_audit TO pat_app;