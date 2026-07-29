-- Migration 009: Add CSP Violation Store
-- This migration creates a table for storing CSP violation reports and supporting queries.

CREATE TABLE IF NOT EXISTS csp_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directive TEXT NOT NULL,
    blocked_uri TEXT NOT NULL,
    document_uri TEXT NOT NULL,
    source_file TEXT,
    line_number INTEGER,
    violated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_csp_violations_directive ON csp_violations (directive);
CREATE INDEX IF NOT EXISTS idx_csp_violations_blocked_uri ON csp_violations (blocked_uri);
CREATE INDEX IF NOT EXISTS idx_csp_violations_violated_at ON csp_violations (violated_at DESC);
