-- ==============================================================================
-- CyberOps SOC — Super Admin Reference Datasets Aggregate RPC Migration
-- Version: 20261031021500_super_admin_reference_datasets_aggregate_rpc.sql
--
-- Security Invariants & Aggregation Defect Fixes Enforced:
-- 1. Complete metric contract: calculates all 10 SOC Analyst, 12 Security Engineer,
--    and 9 IT Operations metrics/distributions (31 total metrics).
-- 2. STABLE function volatility using statement_timestamp() for deterministic snapshots.
-- 3. Uniform placeholder sentinel filtering ('none', 'null', 'n/a', 'unknown', 'undefined', '').
-- 4. Placeholder-aware two-stage fallback: rejects sentinels on primary columns
--    before evaluating secondary fallback columns.
-- 5. Multi-value tokenization via independent lateral unnesting with ZERO Cartesian products
--    using unambiguous C-style escaped delimiter regex E'[,;|\r\n]+' (supporting commas,
--    semicolons, pipes, LF, and CRLF without splitting ordinary words on the letter 'n').
-- 6. Nullable Descriptive Chart Labels:
--    - Keeps stable identifiers (detection_strategy_attack_id, mitigation_id) intact.
--    - Never substitutes an ID when its descriptive name is missing; returns NULL.
--    - If the same ID has conflicting valid names (COUNT(DISTINCT name) > 1), returns NULL
--      display name without arbitrarily selecting one as authoritative.
-- 7. Normalized Case-Insensitive Log-Source Grouping: groups on LOWER(TRIM(token))
--    while projecting a deterministic display label (MIN(TRIM(token))), keeping
--    KPI count and Top 5 analytics chart perfectly aligned.
-- 8. Deterministic Top 5 selections with explicit ORDER BY count DESC, id ASC inside jsonb_agg().
-- 9. Mathematical mitigation coverage invariant: total_evaluated = mitigated + unmitigated.
-- 10. Mitigation mapping buckets (0, 1, 2, 3+) evaluate distinct valid mitigations per technique.
-- 11. Returns aggregated scalars and distribution arrays ONLY; zero raw records exposed.
-- 12. Gated with three-layer fail-closed checks: auth.uid(), role, and account approval.
-- 13. Locked search_path = pg_catalog, public, pg_temp.
--
-- IMPORTANT DEPLOYMENT NOTE:
-- This migration creates the function without altering table ownership of the underlying
-- knowledge tables. Prior to execution, deployment verification must confirm that the executing
-- role (or designated function owner) possesses table-level SELECT or BYPASSRLS permissions.
-- ==============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.get_reference_datasets_summary()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_caller_id uuid;
  v_caller_role text;
  v_caller_approved boolean;
  v_result jsonb;
BEGIN
  -- 1. Caller Authentication Guard
  v_caller_id := auth.uid();
  IF v_caller_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required'
      USING ERRCODE = '42501',
            HINT = 'Sign in with an authenticated session';
  END IF;

  -- 2. Super Admin Role Guard (NULL-safe fail-closed)
  v_caller_role := public.get_user_role();
  IF v_caller_role IS DISTINCT FROM 'super_admin' THEN
    RAISE EXCEPTION 'Access denied: super_admin role required'
      USING ERRCODE = '42501',
            HINT = 'This function is restricted to Super Administrators';
  END IF;

  -- 3. Account Approval Guard (NULL-safe fail-closed)
  v_caller_approved := public.is_approved();
  IF v_caller_approved IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Access denied: account not approved'
      USING ERRCODE = '42501',
            HINT = 'Account must be approved by an administrator';
  END IF;

  -- 4. Execute Isolated Aggregations
  WITH
  -- ===========================================================================
  -- A. SOC Analyst Knowledge Base (public.soc_analyst_knowledge)
  -- ===========================================================================
  soc_clean AS (
    SELECT
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(techniques_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE UPPER(TRIM(techniques_id)) 
        END, ''
      ) AS tech_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(detection_strategy_attack_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(detection_strategy_attack_id) 
        END, ''
      ) AS strat_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(detection_strategy_name)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(detection_strategy_name) 
        END, ''
      ) AS strat_name,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(analytic_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(analytic_id) 
        END, ''
      ) AS ana_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(data_components_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(data_components_id) 
        END, ''
      ) AS dc_id,
      techniques_tactics,
      techniques_platforms,
      log_source_name
    FROM public.soc_analyst_knowledge
  ),
  soc_totals AS (
    SELECT
      COUNT(*)::int AS total_rows,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques,
      COUNT(DISTINCT strat_id)::int AS distinct_detection_strategies,
      COUNT(DISTINCT ana_id)::int AS distinct_analytics,
      COUNT(DISTINCT dc_id)::int AS distinct_data_components
    FROM soc_clean
  ),
  -- A7. Top 5 techniques by tactic (Canonical Normalization)
  soc_tactics_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(t.token)) = 'reconnaissance' THEN 'Reconnaissance'
        WHEN LOWER(TRIM(t.token)) = 'resource development' THEN 'Resource Development'
        WHEN LOWER(TRIM(t.token)) = 'initial access' THEN 'Initial Access'
        WHEN LOWER(TRIM(t.token)) = 'execution' THEN 'Execution'
        WHEN LOWER(TRIM(t.token)) = 'persistence' THEN 'Persistence'
        WHEN LOWER(TRIM(t.token)) = 'privilege escalation' THEN 'Privilege Escalation'
        WHEN LOWER(TRIM(t.token)) = 'defense evasion' THEN 'Defense Evasion'
        WHEN LOWER(TRIM(t.token)) = 'credential access' THEN 'Credential Access'
        WHEN LOWER(TRIM(t.token)) = 'discovery' THEN 'Discovery'
        WHEN LOWER(TRIM(t.token)) = 'lateral movement' THEN 'Lateral Movement'
        WHEN LOWER(TRIM(t.token)) = 'collection' THEN 'Collection'
        WHEN LOWER(TRIM(t.token)) = 'command and control' THEN 'Command and Control'
        WHEN LOWER(TRIM(t.token)) = 'exfiltration' THEN 'Exfiltration'
        WHEN LOWER(TRIM(t.token)) = 'impact' THEN 'Impact'
        ELSE INITCAP(TRIM(t.token))
      END AS canonical_tactic
    FROM soc_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.techniques_tactics, ''), E'[,;|\r\n]+') AS t(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(t.token) <> ''
      AND LOWER(TRIM(t.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  soc_tactics_agg AS (
    SELECT
      canonical_tactic AS tactic,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM soc_tactics_split
    GROUP BY canonical_tactic
    ORDER BY distinct_techniques DESC, tactic ASC
    LIMIT 5
  ),
  -- A6 & A8. Log sources KPI and Top 5 analytics by log source (Normalized Case-Insensitive Grouping)
  soc_log_sources_split AS (
    SELECT
      c.tech_id,
      c.ana_id,
      LOWER(TRIM(l.token)) AS log_source_key,
      TRIM(l.token) AS raw_log_source
    FROM soc_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.log_source_name, ''), E'[,;|\r\n]+') AS l(token)
    WHERE TRIM(l.token) <> ''
      AND LOWER(TRIM(l.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  soc_log_sources_kpi AS (
    SELECT COUNT(DISTINCT log_source_key)::int AS distinct_log_sources
    FROM soc_log_sources_split
  ),
  soc_analytics_by_log_source_agg AS (
    SELECT
      MIN(raw_log_source) AS log_source,
      COUNT(DISTINCT ana_id)::int AS distinct_analytics
    FROM soc_log_sources_split
    WHERE ana_id IS NOT NULL
    GROUP BY log_source_key
    ORDER BY distinct_analytics DESC, log_source ASC
    LIMIT 5
  ),
  -- A9. Top 5 techniques by platform (Canonical Normalization)
  soc_platforms_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(p.token)) = 'windows' THEN 'Windows'
        WHEN LOWER(TRIM(p.token)) = 'linux' THEN 'Linux'
        WHEN LOWER(TRIM(p.token)) IN ('macos', 'mac') THEN 'macOS'
        WHEN LOWER(TRIM(p.token)) IN ('containers', 'container') THEN 'Containers'
        WHEN LOWER(TRIM(p.token)) = 'kubernetes' THEN 'Kubernetes'
        WHEN LOWER(TRIM(p.token)) = 'network' THEN 'Network'
        WHEN LOWER(TRIM(p.token)) = 'iaas' THEN 'IaaS'
        WHEN LOWER(TRIM(p.token)) = 'saas' THEN 'SaaS'
        WHEN LOWER(TRIM(p.token)) = 'paas' THEN 'PaaS'
        WHEN LOWER(TRIM(p.token)) = 'esxi' THEN 'ESXi'
        WHEN UPPER(TRIM(p.token)) = 'PRE' THEN 'PRE'
        ELSE INITCAP(TRIM(p.token))
      END AS canonical_platform
    FROM soc_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.techniques_platforms, ''), E'[,;|\r\n]+') AS p(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(p.token) <> ''
      AND LOWER(TRIM(p.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  soc_platforms_agg AS (
    SELECT
      canonical_platform AS platform,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM soc_platforms_split
    GROUP BY canonical_platform
    ORDER BY distinct_techniques DESC, platform ASC
    LIMIT 5
  ),
  -- A10. Top 5 detection strategies by techniques (With Nullable Descriptive Strategy Names)
  -- If multiple distinct valid names exist for the same ID, returns NULL (ambiguous/conflicting).
  soc_strat_agg AS (
    SELECT
      strat_id AS detection_strategy_attack_id,
      CASE 
        WHEN COUNT(DISTINCT strat_name) = 1 THEN MIN(strat_name)
        ELSE NULL
      END AS detection_strategy_name,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM soc_clean
    WHERE strat_id IS NOT NULL AND tech_id IS NOT NULL
    GROUP BY strat_id
    ORDER BY distinct_techniques DESC, detection_strategy_attack_id ASC
    LIMIT 5
  ),
  soc_summary AS (
    SELECT
      st.total_rows,
      st.distinct_techniques,
      st.distinct_detection_strategies,
      st.distinct_analytics,
      st.distinct_data_components,
      sl.distinct_log_sources,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('tactic', tactic, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, tactic ASC
        ) FROM soc_tactics_agg
      ), '[]'::jsonb) AS top_5_techniques_by_tactic,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('log_source', log_source, 'analytics', distinct_analytics)
          ORDER BY distinct_analytics DESC, log_source ASC
        ) FROM soc_analytics_by_log_source_agg
      ), '[]'::jsonb) AS top_5_analytics_by_log_source,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('platform', platform, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, platform ASC
        ) FROM soc_platforms_agg
      ), '[]'::jsonb) AS top_5_techniques_by_platform,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object(
            'detection_strategy_attack_id', detection_strategy_attack_id,
            'detection_strategy_name', detection_strategy_name,
            'techniques', distinct_techniques
          )
          ORDER BY distinct_techniques DESC, detection_strategy_attack_id ASC
        ) FROM soc_strat_agg
      ), '[]'::jsonb) AS top_5_detection_strategies_by_techniques
    FROM soc_totals st
    CROSS JOIN soc_log_sources_kpi sl
  ),

  -- ===========================================================================
  -- B. Security Engineer Knowledge Base (public.security_engineer_knowledge)
  -- ===========================================================================
  sec_clean AS (
    SELECT
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(technique_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE UPPER(TRIM(technique_id)) 
        END, ''
      ) AS tech_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(mitigation_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE UPPER(TRIM(mitigation_id)) 
        END, ''
      ) AS mit_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(mitigation_name)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(mitigation_name) 
        END, ''
      ) AS mit_name,
      -- B4. Fallback Precedence: tactic_names preferred, technique_tactics fallback
      CASE
        WHEN NULLIF(TRIM(tactic_names), '') IS NOT NULL 
         AND LOWER(TRIM(tactic_names)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(tactic_names)
        WHEN NULLIF(TRIM(technique_tactics), '') IS NOT NULL 
         AND LOWER(TRIM(technique_tactics)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(technique_tactics)
        ELSE NULL
      END AS resolved_tactics,
      -- B5. Fallback Precedence: matched_platform_names preferred, technique_platforms fallback
      CASE
        WHEN NULLIF(TRIM(matched_platform_names), '') IS NOT NULL 
         AND LOWER(TRIM(matched_platform_names)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(matched_platform_names)
        WHEN NULLIF(TRIM(technique_platforms), '') IS NOT NULL 
         AND LOWER(TRIM(technique_platforms)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(technique_platforms)
        ELSE NULL
      END AS resolved_platforms
    FROM public.security_engineer_knowledge
  ),
  sec_totals AS (
    SELECT
      COUNT(*)::int AS total_rows,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques,
      COUNT(DISTINCT mit_id)::int AS distinct_mitigations
    FROM sec_clean
  ),
  -- B4 KPI & B10 Chart: Tactics (Unified Canonical Normalization)
  sec_tactics_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(t.token)) = 'reconnaissance' THEN 'Reconnaissance'
        WHEN LOWER(TRIM(t.token)) = 'resource development' THEN 'Resource Development'
        WHEN LOWER(TRIM(t.token)) = 'initial access' THEN 'Initial Access'
        WHEN LOWER(TRIM(t.token)) = 'execution' THEN 'Execution'
        WHEN LOWER(TRIM(t.token)) = 'persistence' THEN 'Persistence'
        WHEN LOWER(TRIM(t.token)) = 'privilege escalation' THEN 'Privilege Escalation'
        WHEN LOWER(TRIM(t.token)) = 'defense evasion' THEN 'Defense Evasion'
        WHEN LOWER(TRIM(t.token)) = 'credential access' THEN 'Credential Access'
        WHEN LOWER(TRIM(t.token)) = 'discovery' THEN 'Discovery'
        WHEN LOWER(TRIM(t.token)) = 'lateral movement' THEN 'Lateral Movement'
        WHEN LOWER(TRIM(t.token)) = 'collection' THEN 'Collection'
        WHEN LOWER(TRIM(t.token)) = 'command and control' THEN 'Command and Control'
        WHEN LOWER(TRIM(t.token)) = 'exfiltration' THEN 'Exfiltration'
        WHEN LOWER(TRIM(t.token)) = 'impact' THEN 'Impact'
        ELSE INITCAP(TRIM(t.token))
      END AS canonical_tactic
    FROM sec_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.resolved_tactics, ''), E'[,;|\r\n]+') AS t(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(t.token) <> ''
      AND LOWER(TRIM(t.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  sec_tactics_kpi AS (
    SELECT COUNT(DISTINCT canonical_tactic)::int AS distinct_tactics
    FROM sec_tactics_split
  ),
  sec_tactics_agg AS (
    SELECT
      canonical_tactic AS tactic,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM sec_tactics_split
    GROUP BY canonical_tactic
    ORDER BY distinct_techniques DESC, tactic ASC
    LIMIT 5
  ),
  -- B5 KPI & B11 Chart: Platforms (Unified Canonical Normalization)
  sec_platforms_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(p.token)) = 'windows' THEN 'Windows'
        WHEN LOWER(TRIM(p.token)) = 'linux' THEN 'Linux'
        WHEN LOWER(TRIM(p.token)) IN ('macos', 'mac') THEN 'macOS'
        WHEN LOWER(TRIM(p.token)) IN ('containers', 'container') THEN 'Containers'
        WHEN LOWER(TRIM(p.token)) = 'kubernetes' THEN 'Kubernetes'
        WHEN LOWER(TRIM(p.token)) = 'network' THEN 'Network'
        WHEN LOWER(TRIM(p.token)) = 'iaas' THEN 'IaaS'
        WHEN LOWER(TRIM(p.token)) = 'saas' THEN 'SaaS'
        WHEN LOWER(TRIM(p.token)) = 'paas' THEN 'PaaS'
        WHEN LOWER(TRIM(p.token)) = 'esxi' THEN 'ESXi'
        WHEN UPPER(TRIM(p.token)) = 'PRE' THEN 'PRE'
        ELSE INITCAP(TRIM(p.token))
      END AS canonical_platform
    FROM sec_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.resolved_platforms, ''), E'[,;|\r\n]+') AS p(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(p.token) <> ''
      AND LOWER(TRIM(p.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  sec_platforms_kpi AS (
    SELECT COUNT(DISTINCT canonical_platform)::int AS distinct_platforms
    FROM sec_platforms_split
  ),
  sec_platforms_agg AS (
    SELECT
      canonical_platform AS platform,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM sec_platforms_split
    GROUP BY canonical_platform
    ORDER BY distinct_techniques DESC, platform ASC
    LIMIT 5
  ),
  -- B6, B7, B8, B12: Mitigation evaluation and mapping buckets
  sec_tech_mitigation_eval AS (
    SELECT
      tech_id,
      COUNT(DISTINCT mit_id)::int AS valid_mitigations_count
    FROM sec_clean
    WHERE tech_id IS NOT NULL
    GROUP BY tech_id
  ),
  sec_coverage_summary AS (
    SELECT
      COUNT(*)::int AS total_evaluated_techniques,
      COUNT(*) FILTER (WHERE valid_mitigations_count > 0)::int AS mitigated_techniques_count,
      COUNT(*) FILTER (WHERE valid_mitigations_count = 0)::int AS unmitigated_techniques_count,
      -- B12. Distinct mitigation mapping count buckets
      jsonb_build_object(
        'zero_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count = 0)::int,
        'one_mitigation', COUNT(*) FILTER (WHERE valid_mitigations_count = 1)::int,
        'two_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count = 2)::int,
        'three_plus_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count >= 3)::int
      ) AS mitigation_mapping_buckets
    FROM sec_tech_mitigation_eval
  ),
  -- B9. Top 5 mitigations by techniques (With Nullable Descriptive Mitigation Names)
  -- If multiple distinct valid names exist for the same ID, returns NULL (ambiguous/conflicting).
  sec_mitigations_agg AS (
    SELECT
      mit_id AS mitigation_id,
      CASE 
        WHEN COUNT(DISTINCT mit_name) = 1 THEN MIN(mit_name)
        ELSE NULL
      END AS mitigation_name,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM sec_clean
    WHERE mit_id IS NOT NULL AND tech_id IS NOT NULL
    GROUP BY mit_id
    ORDER BY distinct_techniques DESC, mitigation_id ASC
    LIMIT 5
  ),
  sec_summary AS (
    SELECT
      st.total_rows,
      st.distinct_techniques,
      st.distinct_mitigations,
      stk.distinct_tactics,
      spk.distinct_platforms,
      sc.mitigated_techniques_count,
      sc.unmitigated_techniques_count,
      COALESCE(ROUND((sc.mitigated_techniques_count::numeric / NULLIF(st.distinct_techniques, 0)::numeric) * 100, 1), 0.0) AS mitigation_coverage_pct,
      sc.mitigation_mapping_buckets,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object(
            'mitigation_id', mitigation_id,
            'mitigation_name', mitigation_name,
            'techniques', distinct_techniques
          )
          ORDER BY distinct_techniques DESC, mitigation_id ASC
        ) FROM sec_mitigations_agg
      ), '[]'::jsonb) AS top_5_mitigations_by_techniques,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('tactic', tactic, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, tactic ASC
        ) FROM sec_tactics_agg
      ), '[]'::jsonb) AS top_5_techniques_by_tactic,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('platform', platform, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, platform ASC
        ) FROM sec_platforms_agg
      ), '[]'::jsonb) AS top_5_techniques_by_platform
    FROM sec_totals st
    CROSS JOIN sec_tactics_kpi stk
    CROSS JOIN sec_platforms_kpi spk
    CROSS JOIN sec_coverage_summary sc
  ),

  -- ===========================================================================
  -- C. IT Operations Knowledge Base (public.it_operations_knowledge)
  -- ===========================================================================
  it_clean AS (
    SELECT
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(technique_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE UPPER(TRIM(technique_id)) 
        END, ''
      ) AS tech_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(mitigation_id)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE UPPER(TRIM(mitigation_id)) 
        END, ''
      ) AS mit_id,
      NULLIF(
        CASE 
          WHEN LOWER(TRIM(mitigation_name)) IN ('none','null','n/a','unknown','undefined','') THEN NULL 
          ELSE TRIM(mitigation_name) 
        END, ''
      ) AS mit_name,
      -- C5. Fallback Precedence: platform_name preferred, technique_platforms fallback
      CASE
        WHEN NULLIF(TRIM(platform_name), '') IS NOT NULL 
         AND LOWER(TRIM(platform_name)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(platform_name)
        WHEN NULLIF(TRIM(technique_platforms), '') IS NOT NULL 
         AND LOWER(TRIM(technique_platforms)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(technique_platforms)
        ELSE NULL
      END AS resolved_platforms,
      -- C3. Fallback Precedence: tactic_name preferred, technique_tactics fallback
      CASE
        WHEN NULLIF(TRIM(tactic_name), '') IS NOT NULL 
         AND LOWER(TRIM(tactic_name)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(tactic_name)
        WHEN NULLIF(TRIM(technique_tactics), '') IS NOT NULL 
         AND LOWER(TRIM(technique_tactics)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
        THEN TRIM(technique_tactics)
        ELSE NULL
      END AS resolved_tactics
    FROM public.it_operations_knowledge
  ),
  it_totals AS (
    SELECT
      COUNT(*)::int AS total_rows,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques,
      COUNT(DISTINCT mit_id)::int AS distinct_mitigations
    FROM it_clean
  ),
  -- C5 KPI & C6 Chart: Platforms (Unified Canonical Normalization)
  it_platforms_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(p.token)) = 'windows' THEN 'Windows'
        WHEN LOWER(TRIM(p.token)) = 'linux' THEN 'Linux'
        WHEN LOWER(TRIM(p.token)) IN ('macos', 'mac') THEN 'macOS'
        WHEN LOWER(TRIM(p.token)) IN ('containers', 'container') THEN 'Containers'
        WHEN LOWER(TRIM(p.token)) = 'kubernetes' THEN 'Kubernetes'
        WHEN LOWER(TRIM(p.token)) = 'network' THEN 'Network'
        WHEN LOWER(TRIM(p.token)) = 'iaas' THEN 'IaaS'
        WHEN LOWER(TRIM(p.token)) = 'saas' THEN 'SaaS'
        WHEN LOWER(TRIM(p.token)) = 'paas' THEN 'PaaS'
        WHEN LOWER(TRIM(p.token)) = 'esxi' THEN 'ESXi'
        WHEN UPPER(TRIM(p.token)) = 'PRE' THEN 'PRE'
        ELSE INITCAP(TRIM(p.token))
      END AS canonical_platform
    FROM it_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.resolved_platforms, ''), E'[,;|\r\n]+') AS p(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(p.token) <> ''
      AND LOWER(TRIM(p.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  it_platforms_kpi AS (
    SELECT COUNT(DISTINCT canonical_platform)::int AS distinct_platforms
    FROM it_platforms_split
  ),
  it_platforms_agg AS (
    SELECT
      canonical_platform AS platform,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM it_platforms_split
    GROUP BY canonical_platform
    ORDER BY distinct_techniques DESC, platform ASC
    LIMIT 5
  ),
  -- C3 KPI & C7 Chart: Tactics (Unified Canonical Normalization)
  it_tactics_split AS (
    SELECT
      c.tech_id,
      CASE 
        WHEN LOWER(TRIM(t.token)) = 'reconnaissance' THEN 'Reconnaissance'
        WHEN LOWER(TRIM(t.token)) = 'resource development' THEN 'Resource Development'
        WHEN LOWER(TRIM(t.token)) = 'initial access' THEN 'Initial Access'
        WHEN LOWER(TRIM(t.token)) = 'execution' THEN 'Execution'
        WHEN LOWER(TRIM(t.token)) = 'persistence' THEN 'Persistence'
        WHEN LOWER(TRIM(t.token)) = 'privilege escalation' THEN 'Privilege Escalation'
        WHEN LOWER(TRIM(t.token)) = 'defense evasion' THEN 'Defense Evasion'
        WHEN LOWER(TRIM(t.token)) = 'credential access' THEN 'Credential Access'
        WHEN LOWER(TRIM(t.token)) = 'discovery' THEN 'Discovery'
        WHEN LOWER(TRIM(t.token)) = 'lateral movement' THEN 'Lateral Movement'
        WHEN LOWER(TRIM(t.token)) = 'collection' THEN 'Collection'
        WHEN LOWER(TRIM(t.token)) = 'command and control' THEN 'Command and Control'
        WHEN LOWER(TRIM(t.token)) = 'exfiltration' THEN 'Exfiltration'
        WHEN LOWER(TRIM(t.token)) = 'impact' THEN 'Impact'
        ELSE INITCAP(TRIM(t.token))
      END AS canonical_tactic
    FROM it_clean c
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(c.resolved_tactics, ''), E'[,;|\r\n]+') AS t(token)
    WHERE c.tech_id IS NOT NULL
      AND TRIM(t.token) <> ''
      AND LOWER(TRIM(t.token)) NOT IN ('none', 'null', 'n/a', 'unknown', 'undefined')
  ),
  it_tactics_kpi AS (
    SELECT COUNT(DISTINCT canonical_tactic)::int AS distinct_tactics
    FROM it_tactics_split
  ),
  it_tactics_agg AS (
    SELECT
      canonical_tactic AS tactic,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM it_tactics_split
    GROUP BY canonical_tactic
    ORDER BY distinct_techniques DESC, tactic ASC
    LIMIT 5
  ),
  -- C8. Top 5 mitigations by techniques (With Nullable Descriptive Mitigation Names)
  -- If multiple distinct valid names exist for the same ID, returns NULL (ambiguous/conflicting).
  it_mitigations_agg AS (
    SELECT
      mit_id AS mitigation_id,
      CASE 
        WHEN COUNT(DISTINCT mit_name) = 1 THEN MIN(mit_name)
        ELSE NULL
      END AS mitigation_name,
      COUNT(DISTINCT tech_id)::int AS distinct_techniques
    FROM it_clean
    WHERE mit_id IS NOT NULL AND tech_id IS NOT NULL
    GROUP BY mit_id
    ORDER BY distinct_techniques DESC, mitigation_id ASC
    LIMIT 5
  ),
  -- C9. Techniques by mitigation-mapping count
  it_tech_mitigation_eval AS (
    SELECT
      tech_id,
      COUNT(DISTINCT mit_id)::int AS valid_mitigations_count
    FROM it_clean
    WHERE tech_id IS NOT NULL
    GROUP BY tech_id
  ),
  it_mapping_buckets AS (
    SELECT
      jsonb_build_object(
        'zero_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count = 0)::int,
        'one_mitigation', COUNT(*) FILTER (WHERE valid_mitigations_count = 1)::int,
        'two_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count = 2)::int,
        'three_plus_mitigations', COUNT(*) FILTER (WHERE valid_mitigations_count >= 3)::int
      ) AS buckets
    FROM it_tech_mitigation_eval
  ),
  it_summary AS (
    SELECT
      itt.total_rows,
      itt.distinct_techniques,
      itk.distinct_tactics,
      itt.distinct_mitigations,
      ipk.distinct_platforms,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('platform', platform, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, platform ASC
        ) FROM it_platforms_agg
      ), '[]'::jsonb) AS top_5_platforms_by_techniques,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object('tactic', tactic, 'techniques', distinct_techniques)
          ORDER BY distinct_techniques DESC, tactic ASC
        ) FROM it_tactics_agg
      ), '[]'::jsonb) AS top_5_tactics_by_techniques,
      COALESCE((
        SELECT jsonb_agg(
          jsonb_build_object(
            'mitigation_id', mitigation_id,
            'mitigation_name', mitigation_name,
            'techniques', distinct_techniques
          )
          ORDER BY distinct_techniques DESC, mitigation_id ASC
        ) FROM it_mitigations_agg
      ), '[]'::jsonb) AS top_5_mitigations_by_techniques,
      imb.buckets AS mitigation_mapping_buckets
    FROM it_totals itt
    CROSS JOIN it_tactics_kpi itk
    CROSS JOIN it_platforms_kpi ipk
    CROSS JOIN it_mapping_buckets imb
  )

  -- Assemble final JSON structure using statement_timestamp() for STABLE execution semantics
  SELECT jsonb_build_object(
    'summary_generated_at', statement_timestamp(),
    'soc_analyst', (SELECT to_jsonb(soc.*) FROM soc_summary soc),
    'security_engineer', (SELECT to_jsonb(sec.*) FROM sec_summary sec),
    'it_operations', (SELECT to_jsonb(it.*) FROM it_summary it)
  ) INTO v_result;

  RETURN v_result;
END;
$$;

-- Revoke default public execution privileges immediately upon creation
REVOKE ALL ON FUNCTION public.get_reference_datasets_summary() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_reference_datasets_summary() FROM anon;

-- Grant execution strictly to authenticated sessions (authorization verified internally)
GRANT EXECUTE ON FUNCTION public.get_reference_datasets_summary() TO authenticated;

COMMIT;
