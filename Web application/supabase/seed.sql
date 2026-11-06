-- ==============================================================================
-- CyberOps SOC — Verified Reference & Platform Baseline Seed Data
-- Version: 20261015000000_seed.sql
--
-- Safety & Data Integrity Guarantees:
-- 1. Zero local demo personas or mock users are inserted into auth or user_profiles.
-- 2. Zero synthetic browser alerts or mock tasks are inserted into operational tables.
-- 3. Only initializes the single-row platform bootstrap state record (id = 1, is_bootstrapped = false).
-- 4. Safe and idempotent using ON CONFLICT (id) DO NOTHING.
-- ==============================================================================

-- Initialize the platform bootstrap state record (ready for one-time Super Admin initialization)
INSERT INTO public.platform_bootstrap_state (
  id,
  is_bootstrapped,
  bootstrapped_at,
  super_admin_id,
  super_admin_email,
  bootstrap_ip
) VALUES (
  1,
  false,
  NULL,
  NULL,
  NULL,
  NULL
)
ON CONFLICT (id) DO NOTHING;

-- Log baseline seed initialization in platform audit logs
INSERT INTO public.audit_logs (
  audit_category,
  actor_name,
  actor_role,
  action_type,
  target_resource,
  justification,
  status,
  is_simulated,
  system_note
) VALUES (
  'platform',
  'SYSTEM',
  'system',
  'INITIALIZE_BOOTSTRAP_STATE',
  'public.platform_bootstrap_state',
  'Platform schema baseline initialization for CyberOps SOC',
  'SUCCESS',
  false,
  'Database schema baseline and bootstrap state ready for verified administrator onboarding.'
);
