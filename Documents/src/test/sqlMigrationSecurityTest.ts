/**
 * CyberOps SOC — SQL Migration Security Invariants Verification
 *
 * Statically analyzes supabase/migrations/20261015000000_initial_cyberops_soc_schema.sql,
 * supabase/seed.sql, and supabase/rollback_strategy.sql.
 *
 * Verifies:
 * 1. Schema object definitions & RLS activation across all tables
 * 2. Super Admin isolation from operational alerts, notes, and tasks
 * 3. IT Operations scoped record access
 * 4. Anti-self-approval and last active Super Admin triggers
 * 5. Immutable WORM audit logs and notes
 * 6. Hardened SECURITY DEFINER search_path settings
 * 7. Absence of destructive DROP TABLE ... CASCADE commands
 * 8. Zero demo mock personas or fake alerts in seed data
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../');

function runSqlMigrationSecurityTests() {
  console.log('=== RUNNING SQL MIGRATION SECURITY INVARIANTS TESTS ===');
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      console.log(`  [PASS] Test ${passed + failed + 1}: ${message}`);
      passed++;
    } else {
      console.error(`  [FAIL] Test ${passed + failed + 1}: ${message}`);
      failed++;
    }
  }

  const migrationPath = path.resolve(rootDir, 'supabase/migrations/20261015000000_initial_cyberops_soc_schema.sql');
  const seedPath = path.resolve(rootDir, 'supabase/seed.sql');
  const rollbackPath = path.resolve(rootDir, 'supabase/rollback_strategy.sql');

  assert(fs.existsSync(migrationPath), 'Migration artifact 20261015000000_initial_cyberops_soc_schema.sql exists');
  assert(fs.existsSync(seedPath), 'Seed artifact seed.sql exists');
  assert(fs.existsSync(rollbackPath), 'Rollback artifact rollback_strategy.sql exists');

  const migrationSql = fs.readFileSync(migrationPath, 'utf8');
  const seedSql = fs.readFileSync(seedPath, 'utf8');
  const rollbackSql = fs.readFileSync(rollbackPath, 'utf8');

  // Helper to strip single-line SQL comments
  const stripComments = (sql: string) => sql.replace(/--.*$/gm, '');

  // Helper to normalize SQL whitespace and strip all comments
  const normalizeSql = (sql: string) =>
    sql
      .replace(/--.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\s+/g, ' ')
      .trim();

  // Helper to canonicalize SQL predicate syntax for reliable structural comparison
  const canonicalizePredicate = (sql: string) =>
    normalizeSql(sql)
      .replace(/\s*\(\s*/g, '(')
      .replace(/\s*\)\s*/g, ')')
      .replace(/\s*,\s*/g, ', ');

  // Helper to extract a policy chunk (targeting CREATE POLICY definition)
  function extractPolicyBlock(sql: string, policyName: string): string {
    const createMarker = `CREATE POLICY "${policyName}"`;
    const startIndex = sql.indexOf(createMarker);
    if (startIndex === -1) {
      const fallbackIndex = sql.indexOf(policyName);
      if (fallbackIndex === -1) return '';
      const endIndex = sql.indexOf(';', fallbackIndex);
      return sql.slice(fallbackIndex, endIndex !== -1 ? endIndex : undefined);
    }
    const endIndex = sql.indexOf(';', startIndex);
    return sql.slice(startIndex, endIndex !== -1 ? endIndex : undefined);
  }

  // --- Group 1: Required Database Objects & RLS Activation ---
  console.log('-- Group 1: Required Database Objects & RLS Activation --');

  const requiredTables = [
    'user_profiles',
    'alerts',
    'alert_notes',
    'incident_tasks',
    'audit_logs',
    'platform_bootstrap_state',
  ];

  for (const table of requiredTables) {
    assert(
      migrationSql.includes(`CREATE TABLE IF NOT EXISTS public.${table}`),
      `Table public.${table} is defined with CREATE TABLE IF NOT EXISTS`
    );
    assert(
      migrationSql.includes(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;`),
      `Table public.${table} has Row-Level Security (RLS) explicitly enabled`
    );
  }

  // --- Group 2: Role Isolation & Least Privilege Policies ---
  console.log('-- Group 2: Role Isolation & Least Privilege Policies --');

  // Super Admin operational isolation in alerts_select_policy
  const alertsSelectBlock = stripComments(extractPolicyBlock(migrationSql, 'alerts_select_policy'));
  assert(
    alertsSelectBlock.includes("public.get_user_role() IN ('soc_analyst', 'security_engineer')") &&
      !alertsSelectBlock.includes('super_admin'),
    'alerts_select_policy isolates Super Admin by strictly omitting super_admin from permitted roles'
  );

  // Investigation notes isolation in notes_select_policy
  const notesSelectBlock = stripComments(extractPolicyBlock(migrationSql, 'notes_select_policy'));
  assert(
    notesSelectBlock.includes("public.get_user_role() = 'soc_analyst'") &&
      !notesSelectBlock.includes('super_admin') &&
      !notesSelectBlock.includes('security_engineer') &&
      !notesSelectBlock.includes('it_operations'),
    'notes_select_policy restricts investigation notes strictly to soc_analyst'
  );

  // Incident tasks isolation in tasks_select_policy
  const tasksSelectBlock = stripComments(extractPolicyBlock(migrationSql, 'tasks_select_policy'));
  assert(
    tasksSelectBlock.includes("public.get_user_role() = 'soc_analyst'") &&
      tasksSelectBlock.includes("assigned_role = 'security_engineer'") &&
      tasksSelectBlock.includes("assigned_role = 'it_operations'") &&
      !tasksSelectBlock.includes('super_admin'),
    'tasks_select_policy isolates Super Admin from incident remediation tasks'
  );

  // IT Operations scoped access with caller role & approval checks
  assert(
    migrationSql.includes('get_it_ops_assigned_alert_ids') &&
      migrationSql.includes('public.get_it_ops_assigned_alert_ids()') &&
      migrationSql.includes('public.is_approved() = true') &&
      migrationSql.includes("public.get_user_role() = 'it_operations'"),
    'IT Operations alert access is strictly scoped via get_it_ops_assigned_alert_ids() with caller role and approval enforcement'
  );

  // Preserve declarative LANGUAGE sql implementation for IT Operations alert helper
  assert(
    migrationSql.includes('CREATE OR REPLACE FUNCTION public.get_it_ops_assigned_alert_ids()') &&
      migrationSql.includes('LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;'),
    'get_it_ops_assigned_alert_ids helper function preserves LANGUAGE sql STABLE SECURITY DEFINER implementation'
  );

  // Audit log segregation
  assert(
    migrationSql.includes("audit_category = 'platform' AND public.get_user_role() = 'super_admin'") &&
      migrationSql.includes("audit_category = 'operational' AND public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations')"),
    'audit_logs RLS segregates platform audit logs from operational logs'
  );

  // --- Group 2.1: RLS Policy Idempotency & Drop Guards ---
  console.log('-- Group 2.1: RLS Policy Idempotency & Drop Guards --');

  interface ExpectedPolicySpec {
    name: string;
    table: string;
    command: 'SELECT' | 'INSERT' | 'UPDATE' | 'ALL';
    roles: string;
    usingClause?: string;
    withCheckClause?: string;
    disallowUsing?: boolean;
    disallowWithCheck?: boolean;
  }

  const expectedPolicySpecs: ExpectedPolicySpec[] = [
    {
      name: 'bootstrap_read_policy',
      table: 'platform_bootstrap_state',
      command: 'SELECT',
      roles: 'authenticated, anon',
      usingClause: '(true)',
      disallowWithCheck: true,
    },
    {
      name: 'bootstrap_admin_mutation',
      table: 'platform_bootstrap_state',
      command: 'ALL',
      roles: 'service_role',
      usingClause: '(true)',
      withCheckClause: '(true)',
    },
    {
      name: 'profiles_select_policy',
      table: 'user_profiles',
      command: 'SELECT',
      roles: 'authenticated',
      usingClause: "(id = auth.uid() OR (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved'))",
      disallowWithCheck: true,
    },
    {
      name: 'profiles_insert_policy',
      table: 'user_profiles',
      command: 'INSERT',
      roles: 'authenticated',
      withCheckClause: '(id = auth.uid())',
      disallowUsing: true,
    },
    {
      name: 'profiles_update_policy',
      table: 'user_profiles',
      command: 'UPDATE',
      roles: 'authenticated',
      usingClause: "(id = auth.uid() OR (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved'))",
      withCheckClause: "(id = auth.uid() OR (public.get_user_role() = 'super_admin' AND public.get_user_status() = 'approved'))",
    },
    {
      name: 'alerts_select_policy',
      table: 'alerts',
      command: 'SELECT',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND (public.get_user_role() IN ('soc_analyst', 'security_engineer') OR (public.get_user_role() = 'it_operations' AND id IN (SELECT public.get_it_ops_assigned_alert_ids()))))",
      disallowWithCheck: true,
    },
    {
      name: 'alerts_insert_policy',
      table: 'alerts',
      command: 'INSERT',
      roles: 'authenticated',
      withCheckClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst')",
      disallowUsing: true,
    },
    {
      name: 'alerts_update_policy',
      table: 'alerts',
      command: 'UPDATE',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst')",
      withCheckClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst')",
    },
    {
      name: 'notes_select_policy',
      table: 'alert_notes',
      command: 'SELECT',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst')",
      disallowWithCheck: true,
    },
    {
      name: 'notes_insert_policy',
      table: 'alert_notes',
      command: 'INSERT',
      roles: 'authenticated',
      withCheckClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst' AND author_id = auth.uid() AND author_role = 'soc_analyst')",
      disallowUsing: true,
    },
    {
      name: 'tasks_select_policy',
      table: 'incident_tasks',
      command: 'SELECT',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND (public.get_user_role() = 'soc_analyst' OR (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer') OR (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations')))",
      disallowWithCheck: true,
    },
    {
      name: 'tasks_insert_policy',
      table: 'incident_tasks',
      command: 'INSERT',
      roles: 'authenticated',
      withCheckClause: "(public.get_user_status() = 'approved' AND public.get_user_role() = 'soc_analyst')",
      disallowUsing: true,
    },
    {
      name: 'tasks_update_policy',
      table: 'incident_tasks',
      command: 'UPDATE',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND (public.get_user_role() = 'soc_analyst' OR (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations') OR (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer')))",
      withCheckClause: "(public.get_user_status() = 'approved' AND (public.get_user_role() = 'soc_analyst' OR (public.get_user_role() = 'it_operations' AND assigned_role = 'it_operations') OR (public.get_user_role() = 'security_engineer' AND assigned_role = 'security_engineer')))",
    },
    {
      name: 'audit_select_policy',
      table: 'audit_logs',
      command: 'SELECT',
      roles: 'authenticated',
      usingClause: "(public.get_user_status() = 'approved' AND ((audit_category = 'platform' AND public.get_user_role() = 'super_admin') OR (audit_category = 'operational' AND public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations'))))",
      disallowWithCheck: true,
    },
    {
      name: 'audit_service_insert_policy',
      table: 'audit_logs',
      command: 'INSERT',
      roles: 'service_role',
      withCheckClause: '(true)',
      disallowUsing: true,
    },
    {
      name: 'audit_insert_policy',
      table: 'audit_logs',
      command: 'INSERT',
      roles: 'authenticated',
      withCheckClause: "(public.get_user_status() = 'approved' AND actor_id = auth.uid() AND audit_category = 'operational' AND public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations'))",
      disallowUsing: true,
    },
  ];

  // Regex discovery of all CREATE POLICY and DROP POLICY statements in Migration 1
  const allCreatedPolicies = Array.from(
    migrationSql.matchAll(/CREATE\s+POLICY\s+"([^"]+)"\s+ON\s+public\.([a-zA-Z0-9_]+)/g)
  ).map((m) => ({
    name: m[1],
    table: m[2],
    index: m.index ?? 0,
  }));

  const allDroppedPolicies = Array.from(
    migrationSql.matchAll(/DROP\s+POLICY\s+IF\s+EXISTS\s+"([^"]+)"\s+ON\s+public\.([a-zA-Z0-9_]+);/g)
  ).map((m) => ({
    name: m[1],
    table: m[2],
    index: m.index ?? 0,
    length: m[0].length,
  }));

  const genericCreateMatches = Array.from(migrationSql.matchAll(/\bCREATE\s+POLICY\b/gi));
  const genericDropMatches = Array.from(migrationSql.matchAll(/\bDROP\s+POLICY\b/gi));

  // 1. Exact count assertions
  assert(
    allCreatedPolicies.length === 16 && genericCreateMatches.length === 16,
    `Migration 1 defines exactly 16 CREATE POLICY statements (found ${allCreatedPolicies.length})`
  );
  assert(
    allDroppedPolicies.length === 16 && genericDropMatches.length === 16,
    `Migration 1 defines exactly 16 DROP POLICY IF EXISTS statements (found ${allDroppedPolicies.length})`
  );

  // 2. Uniqueness & Anti-Duplication
  const createdNames = allCreatedPolicies.map((p) => p.name);
  const uniqueCreatedNames = new Set(createdNames);
  assert(
    createdNames.length === uniqueCreatedNames.size && createdNames.length === 16,
    'All 16 CREATE POLICY definitions have unique, distinct policy names with zero duplicates'
  );

  const droppedNames = allDroppedPolicies.map((p) => p.name);
  const uniqueDroppedNames = new Set(droppedNames);
  assert(
    droppedNames.length === uniqueDroppedNames.size && droppedNames.length === 16,
    'All 16 DROP POLICY IF EXISTS statements have unique, distinct policy names with zero duplicates'
  );

  // 3. Set Equivalence & Target Table Mapping
  const expectedPolicyMap = new Map(expectedPolicySpecs.map((p) => [p.name, p.table]));
  const unexpectedCreates = allCreatedPolicies.filter((p) => expectedPolicyMap.get(p.name) !== p.table);
  const unexpectedDrops = allDroppedPolicies.filter((p) => expectedPolicyMap.get(p.name) !== p.table);

  assert(
    unexpectedCreates.length === 0,
    `Zero unexpected, duplicate, or misnamed CREATE POLICY statements found (unexpected: ${unexpectedCreates.map((p) => p.name).join(', ') || 'none'})`
  );
  assert(
    unexpectedDrops.length === 0,
    `Zero unexpected, duplicate, or misnamed DROP POLICY statements found (unexpected: ${unexpectedDrops.map((p) => p.name).join(', ') || 'none'})`
  );

  // 4. Per-Policy Detailed Integrity: Drop Guard, Create Definition, Global Precedence, Immediate Adjacency, and Clause Security
  for (const spec of expectedPolicySpecs) {
    const { name, table, command, roles, usingClause, withCheckClause, disallowUsing, disallowWithCheck } = spec;
    const dropStatement = `DROP POLICY IF EXISTS "${name}" ON public.${table};`;
    const createStatement = `CREATE POLICY "${name}" ON public.${table}`;

    const dropMatch = allDroppedPolicies.find((p) => p.name === name);
    const createMatch = allCreatedPolicies.find((p) => p.name === name);

    assert(
      dropMatch !== undefined,
      `Policy "${name}" has exact matching drop guard: ${dropStatement}`
    );
    assert(
      createMatch !== undefined,
      `Policy "${name}" has matching create definition: ${createStatement}`
    );
    assert(
      dropMatch !== undefined && createMatch !== undefined && dropMatch.index < createMatch.index,
      `Drop guard for "${name}" occurs before CREATE POLICY statement`
    );

    // Immediate adjacency verification (only whitespace and SQL comments allowed between drop and create)
    if (dropMatch && createMatch) {
      const dropEnd = dropMatch.index + dropMatch.length;
      const createStart = createMatch.index;
      const betweenText = migrationSql.slice(dropEnd, createStart);
      const strippedBetween = betweenText
        .replace(/--.*$/gm, '')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .trim();

      assert(
        strippedBetween === '',
        `Drop guard for "${name}" immediately precedes CREATE POLICY without intervening SQL`
      );
    }

    // Extract and canonicalize policy definition block to verify security clauses
    const rawBlock = extractPolicyBlock(migrationSql, name);
    const canonBlock = canonicalizePredicate(rawBlock);

    const forToClause = `FOR ${command} TO ${roles}`;
    assert(
      canonBlock.includes(canonicalizePredicate(forToClause)),
      `Policy "${name}" enforces command and target roles: ${forToClause}`
    );

    if (usingClause) {
      const expectedUsing = 'USING' + canonicalizePredicate(usingClause);
      assert(
        canonBlock.includes(expectedUsing),
        `Policy "${name}" enforces intended USING expression`
      );
    }

    if (withCheckClause) {
      const expectedCheck = 'WITH CHECK' + canonicalizePredicate(withCheckClause);
      assert(
        canonBlock.includes(expectedCheck),
        `Policy "${name}" enforces intended WITH CHECK expression`
      );
    }

    if (disallowUsing) {
      assert(
        !canonBlock.includes('USING'),
        `Policy "${name}" correctly omits unpermitted USING clause`
      );
    }

    if (disallowWithCheck) {
      assert(
        !canonBlock.includes('WITH CHECK'),
        `Policy "${name}" correctly omits unpermitted WITH CHECK clause`
      );
    }
  }

  // --- Group 3: Integrity Triggers & Anti-Tampering ---
  console.log('-- Group 3: Integrity Triggers & Anti-Tampering --');

  assert(
    migrationSql.includes('chk_anti_self_approval CHECK (approved_by IS NULL OR approved_by <> id)'),
    'user_profiles enforces anti-self-approval check constraint'
  );

  assert(
    migrationSql.includes('Administrators cannot approve themselves or alter their own roles') &&
      migrationSql.includes('OLD.id = auth.uid()'),
    'trg_protect_user_profile_mutation trigger blocks self-approval and self-promotion'
  );

  assert(
    migrationSql.includes('Operators may only update cosmetic profile details') &&
      migrationSql.includes('OLD.email IS DISTINCT FROM NEW.email') &&
      migrationSql.includes('OLD.approved_by IS DISTINCT FROM NEW.approved_by'),
    'trg_protect_user_profile_mutation restricts non-admin profile mutations strictly to cosmetic fields'
  );

  assert(
    migrationSql.includes('trg_protect_incident_task_mutation') &&
      migrationSql.includes('Operators may only update status and completion details on assigned tasks') &&
      migrationSql.includes('OLD.assigned_role IS DISTINCT FROM NEW.assigned_role') &&
      migrationSql.includes('OLD.associated_alert_id IS DISTINCT FROM NEW.associated_alert_id'),
    'trg_protect_incident_task_mutation restricts IT Ops and Security Engineers from modifying task identity, role, or alert linkage'
  );

  assert(
    migrationSql.includes('Cannot demote or disable the last active Super Admin') &&
      migrationSql.includes('active_admin_count < 1'),
    'trg_protect_user_profile_mutation trigger protects last Super Admin from demotion or disabling'
  );

  assert(
    migrationSql.includes('Cannot delete the last active Super Admin') &&
      migrationSql.includes('trg_protect_admin_deletion'),
    'trg_protect_admin_deletion trigger protects last Super Admin from deletion'
  );

  // Group 3.1: Concurrency Serialization Protocol & Bootstrap State Invariant
  assert(
    migrationSql.includes('INSERT INTO public.platform_bootstrap_state (id, is_bootstrapped)') &&
      migrationSql.includes('VALUES (1, false)') &&
      migrationSql.includes('ON CONFLICT (id) DO NOTHING;'),
    'Migration 1 idempotently provisions platform_bootstrap_state singleton row (id = 1)'
  );

  assert(
    migrationSql.includes('PERFORM 1 FROM public.platform_bootstrap_state WHERE id = 1 FOR UPDATE;') &&
      (migrationSql.match(/PERFORM 1 FROM public\.platform_bootstrap_state WHERE id = 1 FOR UPDATE;/g) || []).length === 2,
    'Consistent exclusive locking protocol (FOR UPDATE on platform_bootstrap_state) is enforced in both mutation and deletion trigger paths'
  );

  assert(
    (migrationSql.match(/IF NOT FOUND THEN\s+RAISE EXCEPTION 'Security Policy Invariant Violation: platform_bootstrap_state lock row/g) || []).length === 2,
    'Both mutation and deletion triggers fail closed (RAISE EXCEPTION) if platform_bootstrap_state lock row is missing'
  );

  // Group 3.2: Hardened Audit Log Insert Authorization (Operational-Only for Authenticated Users)
  const auditInsertBlock = stripComments(extractPolicyBlock(migrationSql, 'audit_insert_policy'));
  assert(
    auditInsertBlock.includes("audit_category = 'operational'") &&
      auditInsertBlock.includes("public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations')") &&
      !auditInsertBlock.includes("audit_category = 'platform'"),
    'audit_insert_policy restricts authenticated clients strictly to operational events and forbids direct platform event creation'
  );

  assert(
    migrationSql.includes('audit_service_insert_policy') &&
      migrationSql.includes('FOR INSERT TO service_role'),
    'audit_service_insert_policy allows trusted server-side creation of audit logs via service_role'
  );

  assert(
    migrationSql.includes('trg_audit_logs_immutable_upd') &&
      migrationSql.includes('trg_audit_logs_immutable_del') &&
      migrationSql.includes('Audit log entries are strictly append-only'),
    'audit_logs enforces WORM immutability triggers against UPDATE and DELETE'
  );

  assert(
    migrationSql.includes('trg_notes_immutable_upd') &&
      migrationSql.includes('trg_notes_immutable_del') &&
      migrationSql.includes('Analyst notes are immutable'),
    'alert_notes enforces WORM immutability triggers against UPDATE and DELETE'
  );

  // Group 3.3: Explicit Table-Level Least-Privilege Grants & Revokes
  assert(
    migrationSql.includes('REVOKE ALL ON public.platform_bootstrap_state FROM anon, public;') &&
      migrationSql.includes('REVOKE ALL ON public.audit_logs FROM anon, public;') &&
      migrationSql.includes('GRANT SELECT ON public.platform_bootstrap_state TO anon;') &&
      migrationSql.includes('GRANT SELECT, INSERT, UPDATE ON public.user_profiles TO authenticated;') &&
      !migrationSql.includes('GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_profiles TO authenticated;') &&
      !migrationSql.includes('profiles_delete_policy') &&
      migrationSql.includes('GRANT SELECT, INSERT ON public.audit_logs TO authenticated;'),
    'Explicit least-privilege table grants revoke all from anon and restrict authenticated operations'
  );

  // --- Group 4: Function Hardening & Non-Destructive Safety ---
  console.log('-- Group 4: Function Hardening & Non-Destructive Safety --');

  // Strip SQL single-line comments (-- ...) to count executable statements
  const cleanMigrationSql = stripComments(migrationSql);
  const cleanSeedSql = stripComments(seedSql);
  const cleanRollbackSql = stripComments(rollbackSql);

  const definerStatements = cleanMigrationSql.match(/LANGUAGE\s+(?:sql|plpgsql)\s+.*?SECURITY DEFINER/gi) || [];
  const searchPathStatements = cleanMigrationSql.match(/SET search_path = public, pg_temp;/g) || [];

  assert(
    definerStatements.length === 10 && definerStatements.length === searchPathStatements.length,
    `Every SECURITY DEFINER function (${definerStatements.length}) explicitly sets search_path = public, pg_temp`
  );

  assert(
    migrationSql.includes('REVOKE EXECUTE ON FUNCTION public.get_user_role() FROM public, anon;'),
    'Helper functions revoke execute grants from public and anon'
  );

  // Verify non-destructive rules: zero executable DROP TABLE or DROP SCHEMA statements
  const dropTableRegex = /^\s*DROP\s+(?:TABLE|SCHEMA)\b/im;
  assert(
    !dropTableRegex.test(cleanMigrationSql),
    'Migration script contains ZERO executable DROP TABLE or DROP SCHEMA statements'
  );

  assert(
    !dropTableRegex.test(cleanSeedSql),
    'Seed script contains ZERO executable DROP TABLE or DROP SCHEMA statements'
  );

  assert(
    !dropTableRegex.test(cleanRollbackSql),
    'Rollback strategy contains ZERO executable DROP TABLE or DROP SCHEMA statements'
  );

  // Seed safety (zero mock data)
  assert(
    !seedSql.includes('alex.mercer@soc.internal') &&
      !seedSql.includes('ALT-2026-1049') &&
      !seedSql.includes('usr-analyst-01'),
    'Seed script contains ZERO mock demo personas or synthetic alerts'
  );

  assert(
    seedSql.includes('public.platform_bootstrap_state') &&
      seedSql.includes('is_bootstrapped') &&
      seedSql.includes('false'),
    'Seed script initializes platform_bootstrap_state with is_bootstrapped = false'
  );

  // --- Group 5: Super Admin Bootstrap RPC Security Invariants ---
  console.log('-- Group 5: Super Admin Bootstrap RPC Security Invariants --');

  const migration2Path = path.resolve(__dirname, '../../supabase/migrations/20261016000000_user_registration_and_governance.sql');
  const migration2Sql = fs.readFileSync(migration2Path, 'utf8');

  assert(
    migration2Sql.includes('CREATE OR REPLACE FUNCTION public.bootstrap_initial_super_admin(admin_email TEXT)') &&
      migration2Sql.includes('RETURNS JSONB'),
    'Migration 2 defines public.bootstrap_initial_super_admin RPC function'
  );

  assert(
    migration2Sql.includes('FUNCTION public.bootstrap_initial_super_admin') &&
      migration2Sql.includes('SECURITY DEFINER SET search_path = public, pg_temp;'),
    'bootstrap_initial_super_admin is hardened with SECURITY DEFINER and fixed search_path = public, pg_temp'
  );

  assert(
    migration2Sql.includes('REVOKE ALL ON FUNCTION public.bootstrap_initial_super_admin(TEXT) FROM PUBLIC, anon, authenticated;') &&
      migration2Sql.includes('GRANT EXECUTE ON FUNCTION public.bootstrap_initial_super_admin(TEXT) TO service_role;'),
    'bootstrap_initial_super_admin explicitly revokes execution from PUBLIC/anon/authenticated and grants strictly to service_role'
  );

  assert(
    migration2Sql.includes('PERFORM 1 FROM public.platform_bootstrap_state') &&
      migration2Sql.includes('WHERE id = 1 AND is_bootstrapped = false') &&
      migration2Sql.includes('FOR UPDATE;'),
    'bootstrap_initial_super_admin locks platform_bootstrap_state and fails closed if already bootstrapped'
  );

  assert(
    migration2Sql.includes('SELECT count(*) INTO v_user_count') &&
      migration2Sql.includes('IF v_user_count = 0 THEN') &&
      migration2Sql.includes('IF v_user_count > 1 THEN') &&
      migration2Sql.includes('Ambiguous account lookup') &&
      migration2Sql.includes('SELECT id INTO v_user_id') &&
      !migration2Sql.includes('min(id)'),
    'bootstrap_initial_super_admin unambiguously counts matches and selects single user ID without min(id) aggregate'
  );

  assert(
    migration2Sql.includes('SELECT count(*) INTO v_profile_count') &&
      migration2Sql.includes('IF v_profile_count = 0 THEN') &&
      migration2Sql.includes('IF v_profile_count > 1 THEN') &&
      migration2Sql.includes('Ambiguous profile lookup'),
    'bootstrap_initial_super_admin validates exactly one corresponding user profile exists before modification'
  );

  assert(
    migration2Sql.includes("WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'platform_bootstrap'") &&
      migration2Sql.includes("'platform_bootstrap'"),
    'trg_protect_user_profile_mutation assigns distinct platform_bootstrap action type during Super Admin bootstrap'
  );

  assert(
    migration2Sql.includes("WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'system'") &&
      migration2Sql.includes("v_audit_record.actor_role <> 'system'"),
    'trg_protect_user_profile_mutation attributes service bootstrap actor to system role rather than super_admin'
  );

  assert(
    migration2Sql.includes('GET DIAGNOSTICS v_row_count = ROW_COUNT;') &&
      migration2Sql.includes('IF v_row_count <> 1 THEN') &&
      migration2Sql.includes('Expected exactly 1 user profile to be updated'),
    'bootstrap_initial_super_admin asserts exactly 1 user profile was updated'
  );

  assert(
    migration2Sql.includes('SELECT last_audit_id INTO v_audit_id') &&
      migration2Sql.includes('IF v_audit_id IS NULL THEN') &&
      migration2Sql.includes('Persistent platform audit log ID was not assigned'),
    'bootstrap_initial_super_admin verifies persistent audit log generation and last_audit_id binding'
  );

  assert(
    migration2Sql.includes('FROM public.audit_logs') &&
      migration2Sql.includes('WHERE id = v_audit_id') &&
      migration2Sql.includes('v_audit_record.target_resource IS NULL') &&
      migration2Sql.includes('lower(trim(v_audit_record.target_resource)) <> v_clean_email') &&
      migration2Sql.includes("v_audit_record.action_type <> 'platform_bootstrap'") &&
      migration2Sql.includes("v_audit_record.audit_category <> 'platform'") &&
      migration2Sql.includes("v_audit_record.status <> 'SUCCESS'") &&
      migration2Sql.includes("v_audit_record.actor_role <> 'system'"),
    'bootstrap_initial_super_admin verifies exact referenced audit row, category, action_type, system actor_role, and case-normalized target'
  );

  console.log(`\n=== COMPLETED: ${passed} of ${passed + failed} SQL MIGRATION SECURITY TESTS PASSED ===\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runSqlMigrationSecurityTests();
