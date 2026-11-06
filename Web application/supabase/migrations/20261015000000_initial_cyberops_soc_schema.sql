-- ==============================================================================
-- CyberOps SOC — Initial PostgreSQL Schema & Row-Level Security Migration
-- Version: 20261015000000_initial_cyberops_soc_schema.sql
-- Target: Supabase PostgreSQL (Project: CyberOps-SOC, Region: Mumbai)
--
-- Security Invariants Enforced:
-- 1. Strict Row-Level Security (RLS) on every application table.
-- 2. Complete Super Admin isolation from operational alerts, notes, and tasks.
-- 3. Scoped record access for IT Operations (task-associated alerts only).
-- 4. Investigation notes private strictly to SOC Analysts (hidden from engineers & admins).
-- 5. Anti-self-approval and role-tampering protection via PostgreSQL triggers.
-- 6. Last active Super Admin protection against demotion, disabling, or deletion.
-- 7. Immutable, append-only audit trail (WORM) with platform vs operational segregation.
-- 8. Hardened SECURITY DEFINER functions with search_path = public, pg_temp.
-- 9. Safe, non-destructive migration structure (no DROP TABLE CASCADE).
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. Core Platform State & Profiles
-- ------------------------------------------------------------------------------

-- Platform bootstrap lock: ensures initial Super Admin creation is strictly one-time
CREATE TABLE IF NOT EXISTS public.platform_bootstrap_state (
  id INTEGER PRIMARY KEY DEFAULT 1,
  is_bootstrapped BOOLEAN NOT NULL DEFAULT false,
  bootstrapped_at TIMESTAMPTZ,
  super_admin_id UUID REFERENCES auth.users(id) ON DELETE RESTRICT,
  super_admin_email TEXT,
  bootstrap_ip TEXT,
  CONSTRAINT single_bootstrap_state_row CHECK (id = 1)
);

-- Ensure platform bootstrap singleton lock row exists
INSERT INTO public.platform_bootstrap_state (id, is_bootstrapped)
VALUES (1, false)
ON CONFLICT (id) DO NOTHING;

-- User profiles table extending auth.users
CREATE TABLE IF NOT EXISTS public.user_profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT CHECK (role IN ('soc_analyst', 'security_engineer', 'it_operations', 'super_admin')),
  account_status TEXT NOT NULL DEFAULT 'pending' CHECK (account_status IN ('pending', 'approved', 'disabled')),
  callsign TEXT,
  title TEXT,
  avatar_url TEXT,
  approved_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_anti_self_approval CHECK (approved_by IS NULL OR approved_by <> id)
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_role ON public.user_profiles(role);
CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON public.user_profiles(account_status);

-- ------------------------------------------------------------------------------
-- 2. Operational Security Domain (Alerts, Notes, Tasks)
-- ------------------------------------------------------------------------------

-- Security alerts table
CREATE TABLE IF NOT EXISTS public.alerts (
  id TEXT PRIMARY KEY, -- e.g. 'ALT-2026-1049'
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_triage', 'escalated', 'resolved', 'false_positive')),
  detected_at TIMESTAMPTZ NOT NULL,
  source_ip TEXT NOT NULL,
  destination_ip TEXT,
  host_name TEXT NOT NULL,
  user_name TEXT,
  mitre_technique_id TEXT, -- e.g. 'T1003.001'
  mitre_tactic_id TEXT,    -- e.g. 'TA0006'
  confidence_score INTEGER NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  network_flow_id TEXT,
  assigned_analyst UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  is_synthetic BOOLEAN NOT NULL DEFAULT true,
  provenance TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON public.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON public.alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON public.alerts(mitre_technique_id, mitre_tactic_id);

-- Normalized investigation notes (maps to SecurityAlert.analystNotes in frontend)
CREATE TABLE IF NOT EXISTS public.alert_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id TEXT NOT NULL REFERENCES public.alerts(id) ON DELETE CASCADE,
  author_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  author_role TEXT NOT NULL CHECK (author_role = 'soc_analyst'),
  note_text TEXT NOT NULL CHECK (length(trim(note_text)) > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON public.alert_notes(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_notes_created_at ON public.alert_notes(created_at ASC);

-- Incident remediation and containment tasks
CREATE TABLE IF NOT EXISTS public.incident_tasks (
  id TEXT PRIMARY KEY, -- e.g. 'TSK-2026-001'
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  assigned_role TEXT NOT NULL CHECK (assigned_role IN ('soc_analyst', 'security_engineer', 'it_operations', 'super_admin')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'blocked')),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
  target_asset TEXT NOT NULL,
  suggested_action_type TEXT,
  associated_alert_id TEXT REFERENCES public.alerts(id) ON DELETE SET NULL,
  completed_at TIMESTAMPTZ,
  completed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  completion_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incident_tasks_role ON public.incident_tasks(assigned_role);
CREATE INDEX IF NOT EXISTS idx_incident_tasks_status ON public.incident_tasks(status);
CREATE INDEX IF NOT EXISTS idx_incident_tasks_alert ON public.incident_tasks(associated_alert_id);

-- ------------------------------------------------------------------------------
-- 3. Append-Only Audit Trail (Platform & Operational Segregation)
-- ------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
  audit_category TEXT NOT NULL CHECK (audit_category IN ('platform', 'operational')),
  actor_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('soc_analyst', 'security_engineer', 'it_operations', 'super_admin', 'system')),
  action_type TEXT NOT NULL,
  target_resource TEXT NOT NULL,
  justification TEXT,
  status TEXT NOT NULL CHECK (status IN ('SIMULATED_SUCCESS', 'SIMULATED_FAILED', 'PROPOSED', 'SUCCESS', 'FAILED')),
  associated_alert_id TEXT REFERENCES public.alerts(id) ON DELETE SET NULL,
  is_simulated BOOLEAN NOT NULL DEFAULT true,
  system_note TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_category ON public.audit_logs(audit_category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON public.audit_logs(actor_id);

-- ------------------------------------------------------------------------------
-- 4. Security Helper Functions (SECURITY DEFINER with Fixed Search Path)
-- ------------------------------------------------------------------------------

-- Retrieve role for the current calling session
CREATE OR REPLACE FUNCTION public.get_user_role()
RETURNS TEXT AS $$
  SELECT role FROM public.user_profiles WHERE id = auth.uid();
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;

-- Retrieve account status for the current calling session
CREATE OR REPLACE FUNCTION public.get_user_status()
RETURNS TEXT AS $$
  SELECT account_status FROM public.user_profiles WHERE id = auth.uid();
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;

-- Check if user is approved
CREATE OR REPLACE FUNCTION public.is_approved()
RETURNS BOOLEAN AS $$
  SELECT (account_status = 'approved') FROM public.user_profiles WHERE id = auth.uid();
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;

-- Helper to retrieve task-linked alert IDs for IT Operations
-- Defense-in-depth: returns an empty set if caller is not an approved IT Operations user
CREATE OR REPLACE FUNCTION public.get_it_ops_assigned_alert_ids()
RETURNS SETOF TEXT AS $$
  SELECT DISTINCT associated_alert_id 
  FROM public.incident_tasks 
  WHERE assigned_role = 'it_operations' 
    AND associated_alert_id IS NOT NULL
    AND public.is_approved() = true
    AND public.get_user_role() = 'it_operations';
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;

-- Revoke dangerous public execution grants on helper functions
REVOKE EXECUTE ON FUNCTION public.get_user_role() FROM public, anon;
REVOKE EXECUTE ON FUNCTION public.get_user_status() FROM public, anon;
REVOKE EXECUTE ON FUNCTION public.is_approved() FROM public, anon;
REVOKE EXECUTE ON FUNCTION public.get_it_ops_assigned_alert_ids() FROM public, anon;

GRANT EXECUTE ON FUNCTION public.get_user_role() TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_status() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_approved() TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_it_ops_assigned_alert_ids() TO authenticated;

-- ------------------------------------------------------------------------------
-- 5. Triggers: Anti-Self-Approval, Anti-Demotion, and WORM Immutability
-- ------------------------------------------------------------------------------

-- Trigger A: Default new profile values (ensures new signups are unassigned & pending)
CREATE OR REPLACE FUNCTION public.trg_enforce_new_profile_defaults()
RETURNS TRIGGER AS $$
BEGIN
  -- Force non-privileged defaults on insert regardless of client input
  IF auth.role() <> 'service_role' THEN
    NEW.role := NULL;
    NEW.account_status := 'pending';
    NEW.approved_by := NULL;
    NEW.approved_at := NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_new_profile_defaults ON public.user_profiles;
CREATE TRIGGER trg_new_profile_defaults
  BEFORE INSERT ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_new_profile_defaults();

-- Trigger B: Protect profile mutations, anti-self-approval, and protect last Super Admin
CREATE OR REPLACE FUNCTION public.trg_protect_user_profile_mutation()
RETURNS TRIGGER AS $$
DECLARE
  active_admin_count INTEGER;
BEGIN
  -- Invariant: id and created_at cannot be mutated
  NEW.id := OLD.id;
  NEW.created_at := OLD.created_at;

  -- Non-super-admin users can ONLY modify approved cosmetic fields (name, callsign, title, avatar_url)
  IF auth.role() <> 'service_role' AND (public.get_user_role() <> 'super_admin' OR public.get_user_status() <> 'approved') THEN
    IF (
      OLD.email IS DISTINCT FROM NEW.email OR
      OLD.role IS DISTINCT FROM NEW.role OR
      OLD.account_status IS DISTINCT FROM NEW.account_status OR
      OLD.approved_by IS DISTINCT FROM NEW.approved_by OR
      OLD.approved_at IS DISTINCT FROM NEW.approved_at
    ) THEN
      RAISE EXCEPTION 'Access Denied: Operators may only update cosmetic profile details (name, callsign, title, avatar_url).';
    END IF;
  END IF;

  -- Check for role or status modification
  IF (OLD.role IS DISTINCT FROM NEW.role OR OLD.account_status IS DISTINCT FROM NEW.account_status) THEN
    -- Only approved Super Admins or service_role can change roles/statuses
    IF auth.role() <> 'service_role' THEN
      IF (public.get_user_role() <> 'super_admin' OR public.get_user_status() <> 'approved') THEN
        RAISE EXCEPTION 'Access Denied: Only approved Super Admins can assign roles or change account statuses.';
      END IF;

      -- Anti-self-approval / self-promotion guard
      IF (OLD.id = auth.uid()) THEN
        RAISE EXCEPTION 'Security Policy Violation: Administrators cannot approve themselves or alter their own roles.';
      END IF;
    END IF;

    -- Update audit stamps when approving
    IF (NEW.account_status = 'approved' AND OLD.account_status <> 'approved') THEN
      NEW.approved_by := COALESCE(auth.uid(), OLD.approved_by);
      NEW.approved_at := now();
    END IF;
  END IF;

  -- Protect the last active Super Admin from demotion or disabling
  IF (OLD.role = 'super_admin' AND OLD.account_status = 'approved') AND
     (NEW.role <> 'super_admin' OR NEW.account_status <> 'approved') THEN
    -- Serialize admin demotion checks using consistent exclusive lock on singleton bootstrap state
    PERFORM 1 FROM public.platform_bootstrap_state WHERE id = 1 FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Security Policy Invariant Violation: platform_bootstrap_state lock row (id=1) is missing.';
    END IF;

    SELECT count(*) INTO active_admin_count
    FROM public.user_profiles
    WHERE role = 'super_admin' AND account_status = 'approved' AND id <> OLD.id;

    IF active_admin_count < 1 THEN
      RAISE EXCEPTION 'Security Policy Violation: Cannot demote or disable the last active Super Admin.';
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_protect_profile_mutation ON public.user_profiles;
CREATE TRIGGER trg_protect_profile_mutation
  BEFORE UPDATE ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.trg_protect_user_profile_mutation();

-- Trigger C: Protect last Super Admin from deletion
CREATE OR REPLACE FUNCTION public.trg_protect_last_admin_deletion()
RETURNS TRIGGER AS $$
DECLARE
  active_admin_count INTEGER;
BEGIN
  IF (OLD.role = 'super_admin' AND OLD.account_status = 'approved') THEN
    -- Serialize admin deletion checks using consistent exclusive lock on singleton bootstrap state
    PERFORM 1 FROM public.platform_bootstrap_state WHERE id = 1 FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Security Policy Invariant Violation: platform_bootstrap_state lock row (id=1) is missing.';
    END IF;

    SELECT count(*) INTO active_admin_count
    FROM public.user_profiles
    WHERE role = 'super_admin' AND account_status = 'approved' AND id <> OLD.id;

    IF active_admin_count < 1 THEN
      RAISE EXCEPTION 'Security Policy Violation: Cannot delete the last active Super Admin.';
    END IF;
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_protect_admin_deletion ON public.user_profiles;
CREATE TRIGGER trg_protect_admin_deletion
  BEFORE DELETE ON public.user_profiles
  FOR EACH ROW EXECUTE FUNCTION public.trg_protect_last_admin_deletion();

-- Trigger D: Enforce immutable WORM audit logs (no UPDATE or DELETE allowed)
CREATE OR REPLACE FUNCTION public.trg_enforce_worm_audit_logs()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit Policy Violation: Audit log entries are strictly append-only and cannot be modified or deleted.';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable_upd ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_immutable_upd
  BEFORE UPDATE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_worm_audit_logs();

DROP TRIGGER IF EXISTS trg_audit_logs_immutable_del ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_immutable_del
  BEFORE DELETE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_worm_audit_logs();

-- Trigger E: Enforce immutable notes (no UPDATE or DELETE allowed)
CREATE OR REPLACE FUNCTION public.trg_enforce_immutable_notes()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Investigation Policy Violation: Analyst notes are immutable and cannot be altered or removed.';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_notes_immutable_upd ON public.alert_notes;
CREATE TRIGGER trg_notes_immutable_upd
  BEFORE UPDATE ON public.alert_notes
  FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_immutable_notes();

DROP TRIGGER IF EXISTS trg_notes_immutable_del ON public.alert_notes;
CREATE TRIGGER trg_notes_immutable_del
  BEFORE DELETE ON public.alert_notes
  FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_immutable_notes();

-- Trigger F: Protect incident task mutation and enforce column-level transition rules
CREATE OR REPLACE FUNCTION public.trg_protect_incident_task_mutation()
RETURNS TRIGGER AS $$
BEGIN
  -- Invariants: id and created_at cannot be mutated
  NEW.id := OLD.id;
  NEW.created_at := OLD.created_at;

  -- Operators (IT Ops and Security Engineers) may only update status and completion details
  IF auth.role() <> 'service_role' AND public.get_user_role() <> 'soc_analyst' THEN
    IF (
      OLD.assigned_role IS DISTINCT FROM NEW.assigned_role OR
      OLD.associated_alert_id IS DISTINCT FROM NEW.associated_alert_id OR
      OLD.title IS DISTINCT FROM NEW.title OR
      OLD.description IS DISTINCT FROM NEW.description OR
      OLD.priority IS DISTINCT FROM NEW.priority OR
      OLD.target_asset IS DISTINCT FROM NEW.target_asset OR
      OLD.suggested_action_type IS DISTINCT FROM NEW.suggested_action_type
    ) THEN
      RAISE EXCEPTION 'Access Denied: Operators may only update status and completion details on assigned tasks.';
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS trg_protect_incident_task_mutation ON public.incident_tasks;
CREATE TRIGGER trg_protect_incident_task_mutation
  BEFORE UPDATE ON public.incident_tasks
  FOR EACH ROW EXECUTE FUNCTION public.trg_protect_incident_task_mutation();

-- ------------------------------------------------------------------------------
-- 6. Table-Level Grants & Revokes (Least Privilege Defense-in-Depth)
-- ------------------------------------------------------------------------------

-- Revoke all table privileges from public and anon
REVOKE ALL ON public.platform_bootstrap_state FROM anon, public;
REVOKE ALL ON public.user_profiles FROM anon, public;
REVOKE ALL ON public.alerts FROM anon, public;
REVOKE ALL ON public.alert_notes FROM anon, public;
REVOKE ALL ON public.incident_tasks FROM anon, public;
REVOKE ALL ON public.audit_logs FROM anon, public;

-- Grant minimal public bootstrap read (required to check setup state before auth)
GRANT SELECT ON public.platform_bootstrap_state TO anon;

-- Grant specific operational table privileges to authenticated
GRANT SELECT, INSERT, UPDATE ON public.user_profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.alerts TO authenticated;
GRANT SELECT, INSERT ON public.alert_notes TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.incident_tasks TO authenticated;
GRANT SELECT, INSERT ON public.audit_logs TO authenticated;
GRANT SELECT ON public.platform_bootstrap_state TO authenticated;

-- Ensure service_role maintains full administrative privileges
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;

-- ------------------------------------------------------------------------------
-- 7. Row-Level Security (RLS) Policies
-- ------------------------------------------------------------------------------

-- Enable RLS across all application tables
ALTER TABLE public.platform_bootstrap_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alert_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- RLS: platform_bootstrap_state
-- ------------------------------------------------------------------------------
-- Public can read bootstrap status (needed for initial setup check)
DROP POLICY IF EXISTS "bootstrap_read_policy" ON public.platform_bootstrap_state;
CREATE POLICY "bootstrap_read_policy" ON public.platform_bootstrap_state
  FOR SELECT TO authenticated, anon
  USING (true);

-- Modifications restricted strictly to service_role (Express backend bootstrap route)
DROP POLICY IF EXISTS "bootstrap_admin_mutation" ON public.platform_bootstrap_state;
CREATE POLICY "bootstrap_admin_mutation" ON public.platform_bootstrap_state
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- RLS: user_profiles
-- ------------------------------------------------------------------------------
-- SELECT: Users can view their own profile; approved Super Admins can view all profiles
DROP POLICY IF EXISTS "profiles_select_policy" ON public.user_profiles;
CREATE POLICY "profiles_select_policy" ON public.user_profiles
  FOR SELECT TO authenticated
  USING (
    id = auth.uid() OR
    (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved')
  );

-- INSERT: Authenticated users can insert their own record upon registration
DROP POLICY IF EXISTS "profiles_insert_policy" ON public.user_profiles;
CREATE POLICY "profiles_insert_policy" ON public.user_profiles
  FOR INSERT TO authenticated
  WITH CHECK (
    id = auth.uid()
  );

-- UPDATE: Users can update cosmetic fields on own profile; Super Admin can update approvals and roles
DROP POLICY IF EXISTS "profiles_update_policy" ON public.user_profiles;
CREATE POLICY "profiles_update_policy" ON public.user_profiles
  FOR UPDATE TO authenticated
  USING (
    id = auth.uid() OR
    (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved')
  )
  WITH CHECK (
    id = auth.uid() OR
    (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved')
  );

-- DELETE: User profiles cannot be deleted through client API (managed server-side via service_role)
-- (No DELETE policy created; defaults to DENY ALL)

-- ------------------------------------------------------------------------------
-- RLS: alerts (Super Admin STRICTLY ISOLATED)
-- ------------------------------------------------------------------------------
-- SELECT: SOC Analysts & Security Engineers view all; IT Ops view task-linked only; Super Admin DENIED
DROP POLICY IF EXISTS "alerts_select_policy" ON public.alerts;
CREATE POLICY "alerts_select_policy" ON public.alerts
  FOR SELECT TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    (
      public.get_user_role() IN ('soc_analyst', 'security_engineer') OR
      (public.get_user_role() = 'it_operations' AND id IN (SELECT public.get_it_ops_assigned_alert_ids()))
    )
    -- Notice: super_admin is intentionally absent from permitted roles!
  );

-- INSERT: Only approved SOC Analysts can insert alerts
DROP POLICY IF EXISTS "alerts_insert_policy" ON public.alerts;
CREATE POLICY "alerts_insert_policy" ON public.alerts
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst'
  );

-- UPDATE: Only approved SOC Analysts can update triage status
DROP POLICY IF EXISTS "alerts_update_policy" ON public.alerts;
CREATE POLICY "alerts_update_policy" ON public.alerts
  FOR UPDATE TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst'
  )
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst'
  );

-- DELETE: Alerts cannot be deleted through client API
-- (No DELETE policy created; defaults to DENY ALL)

-- ------------------------------------------------------------------------------
-- RLS: alert_notes (Private Strictly to SOC Analysts)
-- ------------------------------------------------------------------------------
-- SELECT: SOC Analysts ONLY
DROP POLICY IF EXISTS "notes_select_policy" ON public.alert_notes;
CREATE POLICY "notes_select_policy" ON public.alert_notes
  FOR SELECT TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst'
  );

-- INSERT: SOC Analysts ONLY (must attribute to self)
DROP POLICY IF EXISTS "notes_insert_policy" ON public.alert_notes;
CREATE POLICY "notes_insert_policy" ON public.alert_notes
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst' AND
    author_id = auth.uid() AND
    author_role = 'soc_analyst'
  );

-- ------------------------------------------------------------------------------
-- RLS: incident_tasks (Operational Tasks - Super Admin ISOLATED)
-- ------------------------------------------------------------------------------
-- SELECT: Scoped by role
DROP POLICY IF EXISTS "tasks_select_policy" ON public.incident_tasks;
CREATE POLICY "tasks_select_policy" ON public.incident_tasks
  FOR SELECT TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    (
      public.get_user_role() = 'soc_analyst' OR
      (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer') OR
      (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations')
    )
  );

-- INSERT: SOC Analysts create tasks
DROP POLICY IF EXISTS "tasks_insert_policy" ON public.incident_tasks;
CREATE POLICY "tasks_insert_policy" ON public.incident_tasks
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    public.get_user_role() = 'soc_analyst'
  );

-- UPDATE: SOC Analysts can update all tasks; IT Ops & Engineers update tasks assigned to their role
DROP POLICY IF EXISTS "tasks_update_policy" ON public.incident_tasks;
CREATE POLICY "tasks_update_policy" ON public.incident_tasks
  FOR UPDATE TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    (
      public.get_user_role() = 'soc_analyst' OR
      (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations') OR
      (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer')
    )
  )
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    (
      public.get_user_role() = 'soc_analyst' OR
      (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations') OR
      (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer')
    )
  );

-- ------------------------------------------------------------------------------
-- RLS: audit_logs (Segregated Domain Access)
-- ------------------------------------------------------------------------------
-- SELECT: Platform logs to Super Admin; Operational logs to Operational roles
DROP POLICY IF EXISTS "audit_select_policy" ON public.audit_logs;
CREATE POLICY "audit_select_policy" ON public.audit_logs
  FOR SELECT TO authenticated
  USING (
    public.get_user_status() = 'approved' AND
    (
      (audit_category = 'platform' AND public.get_user_role() = 'super_admin') OR
      (audit_category = 'operational' AND public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations'))
    )
  );

-- INSERT: Trusted backend (service_role) can record platform or operational events
DROP POLICY IF EXISTS "audit_service_insert_policy" ON public.audit_logs;
CREATE POLICY "audit_service_insert_policy" ON public.audit_logs
  FOR INSERT TO service_role
  WITH CHECK (true);

-- INSERT: Authenticated operational roles can insert ONLY operational events attributed to themselves
-- Notice: platform audit events are strictly reserved for trusted server-side creation via service_role
DROP POLICY IF EXISTS "audit_insert_policy" ON public.audit_logs;
CREATE POLICY "audit_insert_policy" ON public.audit_logs
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_user_status() = 'approved' AND
    actor_id = auth.uid() AND
    audit_category = 'operational' AND
    public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations')
  );

-- ==============================================================================
-- End of Migration: 20261015000000_initial_cyberops_soc_schema.sql
-- ==============================================================================
