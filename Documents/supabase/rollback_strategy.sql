-- ==============================================================================
-- CyberOps SOC — Non-Destructive Recovery & Rollback Strategy
-- Target: Supabase PostgreSQL (Project: CyberOps-SOC)
--
-- Safety Notice:
-- This script provides NON-DESTRUCTIVE rollback and disaster recovery instructions.
-- In accordance with SOC compliance, it NEVER executes DROP TABLE, DROP SCHEMA,
-- or TRUNCATE. Instead, it disables triggers or archives records safely.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- Scenario A: Reverting Triggers for Emergency Administrative Maintenance
-- (Requires service_role or database owner privileges)
-- ------------------------------------------------------------------------------

-- To pause profile validation triggers for data correction without losing audit history:
-- ALTER TABLE public.user_profiles DISABLE TRIGGER trg_protect_profile_mutation;
-- ALTER TABLE public.user_profiles DISABLE TRIGGER trg_new_profile_defaults;

-- Always re-enable immediately after maintenance:
-- ALTER TABLE public.user_profiles ENABLE TRIGGER trg_protect_profile_mutation;
-- ALTER TABLE public.user_profiles ENABLE TRIGGER trg_new_profile_defaults;

-- ------------------------------------------------------------------------------
-- Scenario B: Reverting / Modifying an Individual RLS Policy Safely
-- ------------------------------------------------------------------------------

-- To revert an RLS policy safely without dropping underlying table data:
-- DROP POLICY IF EXISTS "alerts_select_policy" ON public.alerts;
-- CREATE POLICY "alerts_select_policy" ON public.alerts
--   FOR SELECT TO authenticated
--   USING (...);

-- ------------------------------------------------------------------------------
-- Scenario C: Table Archival (Non-Destructive Replacement)
-- ------------------------------------------------------------------------------

-- If a table schema needs full replacement, RENAME the existing table rather than dropping it
-- to preserve historical audit evidence:
-- ALTER TABLE public.alerts RENAME TO alerts_archived_20261015;
-- ALTER INDEX idx_alerts_status RENAME TO idx_alerts_status_archived;
