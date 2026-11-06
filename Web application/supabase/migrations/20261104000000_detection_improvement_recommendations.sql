-- ==============================================================================
-- CyberOps SOC — Detection Improvement Recommendations Migration
-- Version: 20261104000000_detection_improvement_recommendations.sql
-- Target: Supabase PostgreSQL (Project: CyberOps-SOC)
--
-- Security Invariants Enforced:
-- 1. Dedicated table for Security Engineer ↔ SOC Analyst detection workflow.
-- 2. Complete Super Admin isolation (no operational recommendation access).
-- 3. Complete IT Operations isolation (scoped to host containment only).
-- 4. Immutable append/lifecycle transitions with zero deletion (WORM integrity).
-- 5. Foreign key ON DELETE RESTRICT on created_by: User account deletion cannot
--    cascade-delete immutable operational detection improvement records.
-- 6. BEFORE INSERT trigger enforcing trusted creator identity, role verification,
--    enforced 'proposed' status, and sanitization of reviewer/implementation fields.
-- 7. Role-specific column mutation guards and strict state transitions on UPDATE.
-- 8. Mandatory immutability on all proposal fields after initial acceptance.
-- 9. Automatic, tamper-evident operational audit log creation in public.audit_logs
--    for all recommendation lifecycle actions with real status 'SUCCESS' (is_simulated = false).
-- 10. Public/anon EXECUTE privileges revoked on all SECURITY DEFINER trigger functions.
-- 11. Strict Row-Level Security (RLS) on public.detection_improvement_recommendations.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.detection_improvement_recommendations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL CHECK (length(trim(title)) > 0),
  technique_id TEXT NOT NULL,
  technique_name TEXT NOT NULL,
  tactic_id TEXT NOT NULL,
  tactic_name TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('critical', 'high', 'medium', 'low')),
  detection_gap TEXT NOT NULL CHECK (length(trim(detection_gap)) > 0),
  technical_explanation TEXT NOT NULL CHECK (length(trim(technical_explanation)) > 0),
  proposed_improvement TEXT NOT NULL CHECK (length(trim(proposed_improvement)) > 0),
  supporting_evidence TEXT NOT NULL DEFAULT '',
  related_rule_draft_id TEXT,
  status TEXT NOT NULL CHECK (
    status IN (
      'proposed',
      'accepted',
      'rejected',
      'clarification_requested',
      'in_progress',
      'completed',
      'validated'
    )
  ) DEFAULT 'proposed',
  created_by UUID REFERENCES auth.users(id) ON DELETE RESTRICT,
  created_by_role TEXT NOT NULL DEFAULT 'security_engineer' CHECK (created_by_role = 'security_engineer'),
  created_by_name TEXT NOT NULL,
  reviewed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  reviewed_by_name TEXT,
  soc_feedback TEXT,
  implementation_notes TEXT,
  sigma_draft_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_recommendations_status ON public.detection_improvement_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_recommendations_technique ON public.detection_improvement_recommendations(technique_id);
CREATE INDEX IF NOT EXISTS idx_recommendations_creator ON public.detection_improvement_recommendations(created_by);
CREATE INDEX IF NOT EXISTS idx_recommendations_created_at ON public.detection_improvement_recommendations(created_at DESC);

-- ------------------------------------------------------------------------------
-- Trigger 1: Prevent Deletion of Recommendation Records (WORM Compliance)
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trg_prevent_recommendation_deletion()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit Policy Violation: Detection improvement recommendations are immutable lifecycle records and cannot be deleted.';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.trg_prevent_recommendation_deletion() FROM public, anon;

DROP TRIGGER IF EXISTS trg_recommendation_no_delete ON public.detection_improvement_recommendations;
CREATE TRIGGER trg_recommendation_no_delete
  BEFORE DELETE ON public.detection_improvement_recommendations
  FOR EACH ROW EXECUTE FUNCTION public.trg_prevent_recommendation_deletion();

-- ------------------------------------------------------------------------------
-- Trigger 2: Secure Insert Validation and Sanitization
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trg_protect_recommendation_insert()
RETURNS TRIGGER AS $$
DECLARE
  caller_role TEXT;
  caller_status TEXT;
  v_user_name TEXT;
BEGIN
  -- Service role bypass for automated migrations/seeders
  IF auth.role() = 'service_role' THEN
    RETURN NEW;
  END IF;

  caller_role := public.get_user_role();
  caller_status := public.get_user_status();

  IF caller_status IS DISTINCT FROM 'approved' THEN
    RAISE EXCEPTION 'Access Denied: Only approved operators can create detection recommendations.';
  END IF;

  IF caller_role <> 'security_engineer' THEN
    RAISE EXCEPTION 'Access Denied: Only Security Engineers can create detection recommendations.';
  END IF;

  -- Enforce server-side creator identity; do not trust client-supplied identity
  NEW.created_by := auth.uid();
  NEW.created_by_role := 'security_engineer';

  SELECT name INTO v_user_name FROM public.user_profiles WHERE id = auth.uid();
  NEW.created_by_name := COALESCE(v_user_name, 'Security Engineer');

  -- Recommendations must ALWAYS begin in 'proposed' status
  NEW.status := 'proposed';

  -- Neutralize any client-injected reviewer, feedback, or implementation fields on insert
  NEW.reviewed_by := NULL;
  NEW.reviewed_by_name := NULL;
  NEW.soc_feedback := NULL;
  NEW.implementation_notes := NULL;
  NEW.sigma_draft_reference := NULL;

  -- Timestamp synchronization
  NEW.created_at := now();
  NEW.updated_at := now();

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.trg_protect_recommendation_insert() FROM public, anon;

DROP TRIGGER IF EXISTS trg_protect_recommendation_insert ON public.detection_improvement_recommendations;
CREATE TRIGGER trg_protect_recommendation_insert
  BEFORE INSERT ON public.detection_improvement_recommendations
  FOR EACH ROW EXECUTE FUNCTION public.trg_protect_recommendation_insert();

-- ------------------------------------------------------------------------------
-- Trigger 3: Enforce Role-Specific Column Mutations & State Transitions
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trg_protect_recommendation_mutation()
RETURNS TRIGGER AS $$
DECLARE
  caller_role TEXT;
  caller_status TEXT;
  v_reviewer_name TEXT;
BEGIN
  -- Invariants: Identity and creation metadata cannot be mutated
  NEW.id := OLD.id;
  NEW.created_at := OLD.created_at;
  NEW.created_by := OLD.created_by;
  NEW.created_by_role := OLD.created_by_role;
  NEW.created_by_name := OLD.created_by_name;
  NEW.technique_id := OLD.technique_id;
  NEW.technique_name := OLD.technique_name;
  NEW.tactic_id := OLD.tactic_id;
  NEW.tactic_name := OLD.tactic_name;

  IF auth.role() <> 'service_role' THEN
    caller_role := public.get_user_role();
    caller_status := public.get_user_status();

    IF caller_status IS DISTINCT FROM 'approved' THEN
      RAISE EXCEPTION 'Access Denied: Only approved operators can modify detection recommendations.';
    END IF;

    -- =========================================================================
    -- Case A: SOC Analyst updating recommendations
    -- Allowed to change: status, soc_feedback, reviewed_by, reviewed_by_name
    -- =========================================================================
    IF caller_role = 'soc_analyst' THEN
      -- SOC Analysts cannot alter Security Engineer implementation fields
      IF (OLD.implementation_notes IS DISTINCT FROM NEW.implementation_notes) THEN
        RAISE EXCEPTION 'Access Denied: SOC Analysts cannot modify implementation notes.';
      END IF;
      IF (OLD.sigma_draft_reference IS DISTINCT FROM NEW.sigma_draft_reference) THEN
        RAISE EXCEPTION 'Access Denied: SOC Analysts cannot modify Sigma draft references.';
      END IF;

      -- SOC Analysts cannot alter original proposal fields
      IF (
        OLD.title IS DISTINCT FROM NEW.title OR
        OLD.detection_gap IS DISTINCT FROM NEW.detection_gap OR
        OLD.technical_explanation IS DISTINCT FROM NEW.technical_explanation OR
        OLD.proposed_improvement IS DISTINCT FROM NEW.proposed_improvement OR
        OLD.priority IS DISTINCT FROM NEW.priority OR
        OLD.supporting_evidence IS DISTINCT FROM NEW.supporting_evidence OR
        OLD.related_rule_draft_id IS DISTINCT FROM NEW.related_rule_draft_id
      ) THEN
        RAISE EXCEPTION 'Access Denied: SOC Analysts cannot alter recommendation proposal fields.';
      END IF;

      -- Enforce valid SOC Analyst status transitions
      IF OLD.status IS DISTINCT FROM NEW.status THEN
        IF (OLD.status IN ('proposed', 'clarification_requested') AND NEW.status = 'accepted') THEN
          -- Valid: Analyst accepts recommendation
          NULL;
        ELSIF (OLD.status IN ('proposed', 'clarification_requested') AND NEW.status = 'rejected') THEN
          -- Valid: Analyst rejects recommendation with mandatory feedback
          IF length(trim(COALESCE(NEW.soc_feedback, ''))) < 10 THEN
            RAISE EXCEPTION 'Validation Error: Rejection requires mandatory explanation of at least 10 characters.';
          END IF;
        ELSIF (OLD.status = 'proposed' AND NEW.status = 'clarification_requested') THEN
          -- Valid: Analyst requests clarification with mandatory feedback
          IF length(trim(COALESCE(NEW.soc_feedback, ''))) < 10 THEN
            RAISE EXCEPTION 'Validation Error: Clarification request requires mandatory instructions of at least 10 characters.';
          END IF;
        ELSIF (OLD.status = 'completed' AND NEW.status = 'validated') THEN
          -- Valid: Analyst validates completed improvement
          NULL;
        ELSE
          RAISE EXCEPTION 'Invalid status transition: SOC Analyst cannot transition recommendation from % to %.', OLD.status, NEW.status;
        END IF;
      END IF;

      -- Stamp reviewer identity reliably from auth.uid()
      NEW.reviewed_by := auth.uid();
      SELECT name INTO v_reviewer_name FROM public.user_profiles WHERE id = auth.uid();
      NEW.reviewed_by_name := COALESCE(v_reviewer_name, 'SOC Analyst');

    -- =========================================================================
    -- Case B: Security Engineer updating recommendations
    -- Allowed to change:
    --   1. Proposal fields (ONLY if status is 'proposed' or 'clarification_requested')
    --   2. status (accepted -> in_progress -> completed, or clarification_requested -> proposed)
    --   3. implementation_notes, sigma_draft_reference
    -- =========================================================================
    ELSIF caller_role = 'security_engineer' THEN
      -- Security Engineers cannot alter SOC review feedback or reviewer stamp
      IF (OLD.soc_feedback IS DISTINCT FROM NEW.soc_feedback) THEN
        RAISE EXCEPTION 'Access Denied: Security Engineers cannot alter SOC review feedback.';
      END IF;
      IF (OLD.reviewed_by IS DISTINCT FROM NEW.reviewed_by OR OLD.reviewed_by_name IS DISTINCT FROM NEW.reviewed_by_name) THEN
        RAISE EXCEPTION 'Access Denied: Security Engineers cannot alter reviewer attribution.';
      END IF;

      -- Proposal immutability: Proposal fields may ONLY be modified while status is 'proposed' or 'clarification_requested'.
      -- Once 'accepted', 'in_progress', 'completed', or 'validated', proposal fields are completely frozen.
      IF OLD.status NOT IN ('proposed', 'clarification_requested') THEN
        IF (
          OLD.title IS DISTINCT FROM NEW.title OR
          OLD.detection_gap IS DISTINCT FROM NEW.detection_gap OR
          OLD.technical_explanation IS DISTINCT FROM NEW.technical_explanation OR
          OLD.proposed_improvement IS DISTINCT FROM NEW.proposed_improvement OR
          OLD.priority IS DISTINCT FROM NEW.priority OR
          OLD.supporting_evidence IS DISTINCT FROM NEW.supporting_evidence OR
          OLD.related_rule_draft_id IS DISTINCT FROM NEW.related_rule_draft_id
        ) THEN
          RAISE EXCEPTION 'Access Denied: Recommendation proposal fields are immutable once accepted by SOC Analyst.';
        END IF;
      END IF;

      -- Enforce valid Security Engineer status transitions
      IF OLD.status IS DISTINCT FROM NEW.status THEN
        IF (OLD.status = 'accepted' AND NEW.status = 'in_progress') THEN
          -- Valid: Start implementation
          NULL;
        ELSIF (OLD.status = 'in_progress' AND NEW.status = 'completed') THEN
          -- Valid: Mark completed with mandatory implementation notes
          IF length(trim(COALESCE(NEW.implementation_notes, ''))) < 10 THEN
            RAISE EXCEPTION 'Validation Error: Completing implementation requires notes of at least 10 characters.';
          END IF;
        ELSIF (OLD.status = 'clarification_requested' AND NEW.status = 'proposed') THEN
          -- Valid: Resubmitting clarified recommendation
          NULL;
        ELSE
          RAISE EXCEPTION 'Invalid status transition: Security Engineer cannot transition recommendation from % to %.', OLD.status, NEW.status;
        END IF;
      END IF;

    ELSE
      -- All other roles (IT Operations, Super Admin) are strictly denied
      RAISE EXCEPTION 'Access Denied: Role % is not authorized to modify detection improvement recommendations.', caller_role;
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.trg_protect_recommendation_mutation() FROM public, anon;

DROP TRIGGER IF EXISTS trg_protect_recommendation_mutation ON public.detection_improvement_recommendations;
CREATE TRIGGER trg_protect_recommendation_mutation
  BEFORE UPDATE ON public.detection_improvement_recommendations
  FOR EACH ROW EXECUTE FUNCTION public.trg_protect_recommendation_mutation();

-- ------------------------------------------------------------------------------
-- Trigger 4: Automatic Operational Audit Trail Logging (AFTER INSERT / UPDATE)
-- Uses existing public.audit_logs schema and preserves WORM protection.
-- Status is 'SUCCESS' (real executed action), is_simulated is false.
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trg_audit_recommendation_lifecycle()
RETURNS TRIGGER AS $$
DECLARE
  v_action_type TEXT;
  v_actor_id UUID;
  v_actor_name TEXT;
  v_actor_role TEXT;
  v_justification TEXT;
  v_system_note TEXT;
  v_metadata JSONB;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_action_type := 'recommendation_created';
    v_actor_id := NEW.created_by;
    v_actor_name := NEW.created_by_name;
    v_actor_role := 'security_engineer';
    v_justification := 'Detection recommendation submitted: ' || NEW.title || '. Gap: ' || NEW.detection_gap;
    v_system_note := 'Security Engineer ' || NEW.created_by_name || ' submitted detection recommendation for technique ' || NEW.technique_id || '. Priority: ' || UPPER(NEW.priority) || '.';
    v_metadata := jsonb_build_object(
      'recommendationId', NEW.id,
      'techniqueId', NEW.technique_id,
      'tacticId', NEW.tactic_id,
      'priority', NEW.priority,
      'status', NEW.status
    );

    INSERT INTO public.audit_logs (
      audit_category,
      actor_id,
      actor_name,
      actor_role,
      action_type,
      target_resource,
      justification,
      status,
      is_simulated,
      system_note,
      metadata
    ) VALUES (
      'operational',
      v_actor_id,
      v_actor_name,
      v_actor_role,
      v_action_type,
      'Recommendation ' || NEW.id || ' (' || NEW.technique_id || ')',
      v_justification,
      'SUCCESS',
      false,
      v_system_note,
      v_metadata
    );

  ELSIF TG_OP = 'UPDATE' AND (OLD.status IS DISTINCT FROM NEW.status) THEN
    -- Map lifecycle action type
    IF NEW.status = 'accepted' THEN
      v_action_type := 'recommendation_accepted';
      v_actor_id := NEW.reviewed_by;
      v_actor_name := COALESCE(NEW.reviewed_by_name, 'SOC Analyst');
      v_actor_role := 'soc_analyst';
      v_justification := COALESCE(NEW.soc_feedback, 'SOC Analyst accepted detection recommendation for engineering.');
      v_system_note := 'SOC Analyst ' || v_actor_name || ' approved recommendation ' || NEW.id || ' for engineering implementation.';
    ELSIF NEW.status = 'rejected' THEN
      v_action_type := 'recommendation_rejected';
      v_actor_id := NEW.reviewed_by;
      v_actor_name := COALESCE(NEW.reviewed_by_name, 'SOC Analyst');
      v_actor_role := 'soc_analyst';
      v_justification := NEW.soc_feedback;
      v_system_note := 'SOC Analyst ' || v_actor_name || ' rejected recommendation ' || NEW.id || '. Reason: ' || NEW.soc_feedback;
    ELSIF NEW.status = 'clarification_requested' THEN
      v_action_type := 'recommendation_clarification_requested';
      v_actor_id := NEW.reviewed_by;
      v_actor_name := COALESCE(NEW.reviewed_by_name, 'SOC Analyst');
      v_actor_role := 'soc_analyst';
      v_justification := NEW.soc_feedback;
      v_system_note := 'SOC Analyst ' || v_actor_name || ' requested clarification on recommendation ' || NEW.id || '.';
    ELSIF NEW.status = 'in_progress' THEN
      v_action_type := 'recommendation_implementation_started';
      v_actor_id := auth.uid();
      SELECT name INTO v_actor_name FROM public.user_profiles WHERE id = auth.uid();
      v_actor_name := COALESCE(v_actor_name, NEW.created_by_name);
      v_actor_role := 'security_engineer';
      v_justification := 'Engineering implementation started for recommendation ' || NEW.id || '.';
      v_system_note := 'Security Engineer ' || v_actor_name || ' transitioned recommendation ' || NEW.id || ' to in_progress.';
    ELSIF NEW.status = 'completed' THEN
      v_action_type := 'recommendation_implemented';
      v_actor_id := auth.uid();
      SELECT name INTO v_actor_name FROM public.user_profiles WHERE id = auth.uid();
      v_actor_name := COALESCE(v_actor_name, NEW.created_by_name);
      v_actor_role := 'security_engineer';
      v_justification := NEW.implementation_notes;
      v_system_note := 'Security Engineer ' || v_actor_name || ' completed implementation of recommendation ' || NEW.id || '. Sigma reference: ' || COALESCE(NEW.sigma_draft_reference, 'N/A') || '.';
    ELSIF NEW.status = 'validated' THEN
      v_action_type := 'recommendation_validated';
      v_actor_id := NEW.reviewed_by;
      v_actor_name := COALESCE(NEW.reviewed_by_name, 'SOC Analyst');
      v_actor_role := 'soc_analyst';
      v_justification := COALESCE(NEW.soc_feedback, 'SOC Analyst validated completed detection rule and telemetry.');
      v_system_note := 'SOC Analyst ' || v_actor_name || ' completed final operational validation on recommendation ' || NEW.id || '.';
    ELSIF NEW.status = 'proposed' AND OLD.status = 'clarification_requested' THEN
      v_action_type := 'recommendation_resubmitted';
      v_actor_id := auth.uid();
      SELECT name INTO v_actor_name FROM public.user_profiles WHERE id = auth.uid();
      v_actor_name := COALESCE(v_actor_name, NEW.created_by_name);
      v_actor_role := 'security_engineer';
      v_justification := 'Security Engineer resubmitted clarified recommendation: ' || NEW.title;
      v_system_note := 'Security Engineer ' || v_actor_name || ' resubmitted clarified recommendation ' || NEW.id || ' for review.';
    ELSE
      v_action_type := 'recommendation_status_updated';
      v_actor_id := auth.uid();
      v_actor_name := 'Operator';
      v_actor_role := COALESCE(public.get_user_role(), 'security_engineer');
      v_justification := 'Recommendation status transitioned from ' || OLD.status || ' to ' || NEW.status;
      v_system_note := 'Status transitioned from ' || OLD.status || ' to ' || NEW.status;
    END IF;

    v_metadata := jsonb_build_object(
      'recommendationId', NEW.id,
      'techniqueId', NEW.technique_id,
      'previousStatus', OLD.status,
      'newStatus', NEW.status,
      'sigmaDraftReference', NEW.sigma_draft_reference
    );

    INSERT INTO public.audit_logs (
      audit_category,
      actor_id,
      actor_name,
      actor_role,
      action_type,
      target_resource,
      justification,
      status,
      is_simulated,
      system_note,
      metadata
    ) VALUES (
      'operational',
      v_actor_id,
      v_actor_name,
      v_actor_role,
      v_action_type,
      'Recommendation ' || NEW.id || ' (' || NEW.technique_id || ')',
      v_justification,
      'SUCCESS',
      false,
      v_system_note,
      v_metadata
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.trg_audit_recommendation_lifecycle() FROM public, anon;

DROP TRIGGER IF EXISTS trg_audit_recommendation_lifecycle ON public.detection_improvement_recommendations;
CREATE TRIGGER trg_audit_recommendation_lifecycle
  AFTER INSERT OR UPDATE ON public.detection_improvement_recommendations
  FOR EACH ROW EXECUTE FUNCTION public.trg_audit_recommendation_lifecycle();

-- ------------------------------------------------------------------------------
-- Table Grants & Revokes
-- ------------------------------------------------------------------------------
REVOKE ALL ON public.detection_improvement_recommendations FROM anon, public;
GRANT SELECT, INSERT, UPDATE ON public.detection_improvement_recommendations TO authenticated;
GRANT ALL ON public.detection_improvement_recommendations TO service_role;

-- ------------------------------------------------------------------------------
-- Row-Level Security (RLS) Policies
-- ------------------------------------------------------------------------------
ALTER TABLE public.detection_improvement_recommendations ENABLE ROW LEVEL SECURITY;

-- SELECT: Security Engineers and SOC Analysts only. IT Ops & Super Admin denied.
DROP POLICY IF EXISTS "rec_select_policy" ON public.detection_improvement_recommendations;
CREATE POLICY "rec_select_policy" ON public.detection_improvement_recommendations
  FOR SELECT TO authenticated
  USING (
    public.is_approved() = true AND
    public.get_user_role() IN ('soc_analyst', 'security_engineer')
  );

-- INSERT: Security Engineers create recommendations
DROP POLICY IF EXISTS "rec_insert_policy" ON public.detection_improvement_recommendations;
CREATE POLICY "rec_insert_policy" ON public.detection_improvement_recommendations
  FOR INSERT TO authenticated
  WITH CHECK (
    public.is_approved() = true AND
    public.get_user_role() = 'security_engineer' AND
    (created_by = auth.uid() OR created_by IS NULL)
  );

-- UPDATE: Both roles update per trigger transition rules
DROP POLICY IF EXISTS "rec_update_policy" ON public.detection_improvement_recommendations;
CREATE POLICY "rec_update_policy" ON public.detection_improvement_recommendations
  FOR UPDATE TO authenticated
  USING (
    public.is_approved() = true AND
    public.get_user_role() IN ('soc_analyst', 'security_engineer')
  )
  WITH CHECK (
    public.is_approved() = true AND
    public.get_user_role() IN ('soc_analyst', 'security_engineer')
  );

