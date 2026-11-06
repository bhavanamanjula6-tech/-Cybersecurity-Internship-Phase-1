-- ==============================================================================
-- CyberOps SOC — User Registration & Super Admin Governance Migration
-- Version: 20261016000000_user_registration_and_governance.sql
-- Target: Supabase PostgreSQL (Project: CyberOps-SOC, Region: Mumbai)
--
-- Security Invariants Enforced:
-- 1. Idempotent trigger on auth.users for safe profile provisioning upon signup.
-- 2. New signups automatically receive 'pending' account_status and NULL role.
-- 3. Updates account_status check constraint to support 'rejected' and 'disabled'.
-- 4. Super Admin user governance: Only approved Super Admins can assign operational
--    roles (soc_analyst, security_engineer, it_operations).
-- 5. Anti-Privilege-Escalation: Super Admin role can never be granted via client UI.
-- 6. Anti-Self-Approval: Super Admins cannot approve or modify their own status/role.
-- ==============================================================================

-- 1. Ensure platform bootstrap singleton lock row exists
INSERT INTO public.platform_bootstrap_state (id, is_bootstrapped)
VALUES (1, false)
ON CONFLICT (id) DO NOTHING;

-- 2. Expand account_status check constraint to safely support 'rejected'
ALTER TABLE public.user_profiles 
  DROP CONSTRAINT IF EXISTS user_profiles_account_status_check;

ALTER TABLE public.user_profiles 
  ADD CONSTRAINT user_profiles_account_status_check 
  CHECK (account_status IN ('pending', 'approved', 'disabled', 'rejected'));

-- 3. Add last_audit_id column to user_profiles for exact, tamper-evident audit correlation
ALTER TABLE public.user_profiles 
  ADD COLUMN IF NOT EXISTS last_audit_id UUID REFERENCES public.audit_logs(id);

-- 2. Idempotent database trigger function on auth.users for automated profile provisioning
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  v_name TEXT;
  v_callsign TEXT;
BEGIN
  -- Extract name from user metadata or fallback to email prefix
  v_name := COALESCE(
    NEW.raw_user_meta_data->>'full_name',
    NEW.raw_user_meta_data->>'name',
    split_part(NEW.email, '@', 1)
  );

  -- Derive standard 8-character callsign
  v_callsign := UPPER(SUBSTRING(REGEXP_REPLACE(v_name, '[^a-zA-Z0-9]', '', 'g') FROM 1 FOR 8));
  IF v_callsign = '' OR v_callsign IS NULL THEN
    v_callsign := 'OPERATOR';
  END IF;

  -- Insert non-privileged pending profile row associated with the new authenticated user ID
  INSERT INTO public.user_profiles (
    id,
    email,
    name,
    role,
    account_status,
    callsign,
    title,
    created_at,
    updated_at
  ) VALUES (
    NEW.id,
    NEW.email,
    v_name,
    NULL,
    'pending',
    v_callsign,
    'Pending Operator',
    now(),
    now()
  )
  ON CONFLICT (id) DO NOTHING;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

-- Revoke execute from public/anon
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM public, anon;

-- Bind trigger to auth.users table
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 3. Enhance trg_protect_user_profile_mutation to prevent Super Admin creation via client
CREATE OR REPLACE FUNCTION public.trg_protect_user_profile_mutation()
RETURNS TRIGGER AS $$
DECLARE
  active_admin_count INTEGER;
  v_audit_id UUID;
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
      OLD.approved_at IS DISTINCT FROM NEW.approved_at OR
      OLD.last_audit_id IS DISTINCT FROM NEW.last_audit_id
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

      -- Anti-privilege-escalation: Super Admin role can never be created via client operations
      IF (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN
        RAISE EXCEPTION 'Security Policy Violation: Super Admin role can only be provisioned through server bootstrap.';
      END IF;

      -- Permitted roles restriction: Only operational roles can be assigned by administrators
      IF NEW.role IS NOT NULL AND NEW.role NOT IN ('soc_analyst', 'security_engineer', 'it_operations') THEN
        RAISE EXCEPTION 'Security Policy Violation: Invalid operational role assigned.';
      END IF;
    END IF;

    -- Update audit stamps when approving
    IF (NEW.account_status = 'approved' AND OLD.account_status <> 'approved') THEN
      NEW.approved_by := COALESCE(auth.uid(), OLD.approved_by);
      NEW.approved_at := now();
    END IF;

    -- Atomic platform audit trail for user governance (WORM tamper-evident)
    v_audit_id := gen_random_uuid();
    INSERT INTO public.audit_logs (
      id,
      audit_category,
      actor_id,
      actor_name,
      actor_role,
      action_type,
      target_resource,
      justification,
      status,
      is_simulated,
      system_note
    ) VALUES (
      v_audit_id,
      'platform',
      auth.uid(),
      COALESCE(
        (SELECT name FROM public.user_profiles WHERE id = auth.uid()),
        CASE WHEN auth.role() = 'service_role' THEN 'Platform Bootstrap Service' ELSE 'Platform Administrator' END
      ),
      CASE 
        WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'system'
        ELSE 'super_admin'
      END,
      CASE 
        WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'platform_bootstrap'
        WHEN NEW.account_status = 'approved' THEN 'unlock_account' 
        ELSE 'lock_account' 
      END,
      lower(trim(NEW.email)),
      CASE 
        WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'Initial Super Admin platform bootstrap authorization.'
        WHEN NEW.account_status = 'approved' THEN 'Operator access approved. Assigned role: ' || COALESCE(NEW.role, 'unassigned')
        WHEN NEW.account_status = 'rejected' THEN 'Operator access request rejected.'
        ELSE 'Account status changed to ' || NEW.account_status
      END,
      'SUCCESS',
      false,
      CASE 
        WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'Automated database governance audit record generated during initial Super Admin bootstrap.'
        ELSE 'Automated database governance audit record generated during user_profiles mutation.'
      END
    );

    NEW.last_audit_id := v_audit_id;
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

-- ------------------------------------------------------------------------------
-- 4. Initial Platform Super Admin Bootstrap RPC (One-Time Execution)
-- ------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.bootstrap_initial_super_admin(admin_email TEXT)
RETURNS JSONB AS $$
DECLARE
  v_user_id UUID;
  v_user_count INT;
  v_profile_count INT;
  v_row_count INT;
  v_audit_id UUID;
  v_clean_email TEXT;
  v_audit_record RECORD;
BEGIN
  -- 1. Validate email input format
  v_clean_email := lower(trim(admin_email));
  IF v_clean_email IS NULL OR v_clean_email = '' OR position('@' in v_clean_email) = 0 THEN
    RAISE EXCEPTION 'Bootstrap Validation Error: A valid, non-empty administrator email address is required.';
  END IF;

  -- 2. Concurrency lock & single-use invariant: ensure platform has not already been bootstrapped
  PERFORM 1 FROM public.platform_bootstrap_state 
  WHERE id = 1 AND is_bootstrapped = false 
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Security Policy Invariant Violation: Platform has already been bootstrapped or lock row (id=1) is missing.';
  END IF;

  -- 3. Verify exactly one registered account exists in auth.users for normalized email
  SELECT count(*) INTO v_user_count
  FROM auth.users 
  WHERE lower(trim(email)) = v_clean_email;

  IF v_user_count = 0 THEN
    RAISE EXCEPTION 'Bootstrap Failure: No registered auth account exists for "%". Target user must register first.', v_clean_email;
  END IF;

  IF v_user_count > 1 THEN
    RAISE EXCEPTION 'Bootstrap Security Violation: Ambiguous account lookup. Found % accounts matching "%". Cannot proceed with bootstrap.', v_user_count, v_clean_email;
  END IF;

  -- Distinct single user ID retrieval after count verification without aggregate
  SELECT id INTO v_user_id
  FROM auth.users
  WHERE lower(trim(email)) = v_clean_email;

  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Bootstrap Failure: Could not retrieve unique user ID for "%".', v_clean_email;
  END IF;

  -- Verify exactly one matching profile exists in public.user_profiles
  SELECT count(*) INTO v_profile_count
  FROM public.user_profiles
  WHERE id = v_user_id AND lower(trim(email)) = v_clean_email;

  IF v_profile_count = 0 THEN
    RAISE EXCEPTION 'Bootstrap Failure: No corresponding user profile exists for user ID % and email "%".', v_user_id, v_clean_email;
  END IF;

  IF v_profile_count > 1 THEN
    RAISE EXCEPTION 'Bootstrap Security Violation: Ambiguous profile lookup. Found % profiles matching "%". Cannot proceed with bootstrap.', v_profile_count, v_clean_email;
  END IF;

  -- 4. Elevate the user profile to super_admin and approved status
  -- Note: This statement fires trg_protect_user_profile_mutation which creates the
  -- atomic platform audit log entry and assigns NEW.last_audit_id in the same transaction.
  UPDATE public.user_profiles
  SET role = 'super_admin',
      account_status = 'approved',
      approved_at = now()
  WHERE id = v_user_id AND lower(trim(email)) = v_clean_email;

  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'Bootstrap Failure: Expected exactly 1 user profile to be updated, but updated % rows.', v_row_count;
  END IF;

  -- 5. Verify the atomic governance audit log and last_audit_id were generated
  SELECT last_audit_id INTO v_audit_id
  FROM public.user_profiles
  WHERE id = v_user_id;

  IF v_audit_id IS NULL THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Persistent platform audit log ID was not assigned to user profile.';
  END IF;

  -- Verify exact referenced audit row and expected bootstrap event properties
  SELECT id, audit_category, action_type, target_resource, actor_role, status
  INTO v_audit_record
  FROM public.audit_logs
  WHERE id = v_audit_id;

  IF v_audit_record.id IS NULL THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % referenced by user profile does not exist in public.audit_logs.', v_audit_id;
  END IF;

  IF v_audit_record.audit_category <> 'platform' THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % has invalid category "%". Expected "platform".', v_audit_id, v_audit_record.audit_category;
  END IF;

  IF v_audit_record.action_type <> 'platform_bootstrap' THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % has unexpected action_type "%". Expected "platform_bootstrap".', v_audit_id, v_audit_record.action_type;
  END IF;

  -- Case-insensitive audit target verification handling NULL explicitly
  IF v_audit_record.target_resource IS NULL OR lower(trim(v_audit_record.target_resource)) <> v_clean_email THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % target "%" does not match administrator email "%".', v_audit_id, v_audit_record.target_resource, v_clean_email;
  END IF;

  IF v_audit_record.status <> 'SUCCESS' THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % status is "%". Expected "SUCCESS".', v_audit_id, v_audit_record.status;
  END IF;

  -- Accurate attribution: automated bootstrap by service role is attributed to 'system'
  IF v_audit_record.actor_role <> 'system' THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Audit log record % actor_role is "%". Expected "system".', v_audit_id, v_audit_record.actor_role;
  END IF;

  -- 6. Atomically complete the platform bootstrap singleton record
  UPDATE public.platform_bootstrap_state
  SET is_bootstrapped = true,
      bootstrapped_at = now(),
      super_admin_id = v_user_id,
      super_admin_email = v_clean_email
  WHERE id = 1 AND is_bootstrapped = false;

  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'Bootstrap Invariant Failure: Could not finalize platform_bootstrap_state record.';
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'status', 'BOOTSTRAP_SUCCESS',
    'admin_email', v_clean_email,
    'admin_id', v_user_id,
    'audit_id', v_audit_id,
    'action_type', 'platform_bootstrap',
    'bootstrapped_at', now()
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

-- Revoke execution from PUBLIC, anon, and ordinary authenticated users
REVOKE ALL ON FUNCTION public.bootstrap_initial_super_admin(TEXT) FROM PUBLIC, anon, authenticated;

-- Grant execution exclusively to trusted service_role
GRANT EXECUTE ON FUNCTION public.bootstrap_initial_super_admin(TEXT) TO service_role;

-- ==============================================================================
-- End of Migration: 20261016000000_user_registration_and_governance.sql
-- ==============================================================================
