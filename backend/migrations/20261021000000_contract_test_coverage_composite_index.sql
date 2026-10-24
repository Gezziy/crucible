-- Migration: Add composite index on contract test coverage historical records
-- Resolves #1156: Querying test coverage progression filters by contract_id and sorts by created_at DESC.
-- Adds composite index on (contract_id, created_at DESC) and (project_name, created_at DESC) to eliminate sequential table scans.

CREATE TABLE IF NOT EXISTS test_coverage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id TEXT,
    project_name TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    coverage_percent DOUBLE PRECISION NOT NULL,
    total_lines INTEGER NOT NULL,
    covered_lines INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure contract_id column exists if test_coverage table was previously created without it
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'test_coverage' AND column_name = 'contract_id'
    ) THEN
        ALTER TABLE test_coverage ADD COLUMN contract_id TEXT;
        UPDATE test_coverage SET contract_id = project_name WHERE contract_id IS NULL;
    END IF;
END $$;

-- Composite index on (contract_id, created_at DESC) to optimize progression queries
CREATE INDEX IF NOT EXISTS idx_test_coverage_contract_created_at_desc
    ON test_coverage (contract_id, created_at DESC);

-- Composite index on (project_name, created_at DESC) for project-level historical lookups
CREATE INDEX IF NOT EXISTS idx_test_coverage_project_created_at_desc
    ON test_coverage (project_name, created_at DESC);
