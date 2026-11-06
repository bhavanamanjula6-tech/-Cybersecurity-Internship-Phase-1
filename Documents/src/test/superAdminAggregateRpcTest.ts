/**
 * CyberOps SOC — Super Admin Reference Datasets RPC Foundation Test Suite
 *
 * Comprehensive verification for:
 * 1. Migration Artifact Static Analysis:
 *    - Validates file existence at supabase/migrations/20261031021500_super_admin_reference_datasets_aggregate_rpc.sql
 *    - Validates SECURITY DEFINER and fixed search_path = pg_catalog, public, pg_temp
 *    - Validates statement_timestamp() STABLE volatility alignment
 *    - Validates three-layer defensive gating (auth.uid, role, approval) with IS DISTINCT FROM
 *    - Validates deterministic Top 5 ordering inside jsonb_agg(ORDER BY ...)
 *    - Validates nullable descriptive names with conflicting-name resolution (COUNT(DISTINCT) = 1)
 *    - Validates case-insensitive log source grouping (log_source_key) with deterministic label
 *    - Validates unambiguous C-escaped delimiter E'[,;|\r\n]+' across all 7 unnesting sites
 *    - Validates REVOKE from PUBLIC/anon and GRANT to authenticated
 *    - Validates all 31 metrics across SOC Analyst, Security Engineer, and IT Operations
 * 2. Strict ISO 8601 Timestamp Validation:
 *    - Accepts valid UTC and timezone-offset ISO strings
 *    - Rejects date-only strings, locale strings, non-ISO parseable strings, invalid calendar dates, and empty strings
 * 3. Deep Contract & Invariant Validation:
 *    - Numeric validation: NaN, Infinity, -Infinity, negative counts, fractional counts
 *    - Mitigation buckets: missing each individual bucket field in sec and it, negative/fractional/non-finite buckets, bucket sum mismatches
 *    - Descriptive labels: valid strings, nulls, conflicting-name handling, rejection of empty/whitespace labels
 * 4. Client-Side Authorization & Service Mock Verification:
 *    - Unauthorized callers (pending admin, analyst, engineer, it ops) rejected with AccessDeniedError
 *    - Verified that mocked RPC call count remains exactly zero for all unauthorized callers
 *    - Approved super_admin invokes mocked RPC exactly once with exact function name
 *    - Verifies zero direct table queries (no .from() calls)
 *    - Handles database RPC errors and null payloads gracefully
 * 5. Zero Raw Records Exposure & Role Isolation Invariant:
 *    - Asserts zero alert IDs, task IDs, or user private notes in contract
 * 6. JavaScript-Side Multi-Value Delimiter Regression Tests (Test Runtime Verification Only):
 *    - JavaScript-side regression tests verifying string and regex splitting in the test runtime.
 *    - Note: These run in JavaScript/Node.js; they do not execute PostgreSQL's regular-expression engine or independently verify live PostgreSQL behavior.
 *    - Tests delimiter splitting on commas, semicolons, pipes, LF, CRLF, and mixed strings.
 *    - Proves words containing the letter 'n' are never corrupted or split on 'n' in JavaScript runtime.
 *    - Confirms CRLF leaves no residual \r (0x0D) characters.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validateReferenceDatasetsSummary,
  isValidIso8601Timestamp,
  ReferenceDatasetsSummaryResponse,
} from '../types/superAdminAggregate';
import * as superAdminAggregateModule from '../services/superAdminAggregateService';
import {
  fetchReferenceDatasetsSummary,
  AggregateRpcClient,
  SAFE_RPC_ERROR_MESSAGE,
} from '../services/superAdminAggregateService';
import { UserProfile, AccessDeniedError } from '../types/auth';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../');

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

async function runSuperAdminAggregateRpcTests() {
  console.log('=== RUNNING SUPER ADMIN AGGREGATE RPC FOUNDATION TESTS ===\n');

  // =========================================================================
  // Group 1: Migration Artifact Verification
  // =========================================================================
  console.log('-- Group 1: Migration Artifact Verification --');

  const migrationPath = path.resolve(
    rootDir,
    'supabase/migrations/20261031021500_super_admin_reference_datasets_aggregate_rpc.sql'
  );

  assert(fs.existsSync(migrationPath), 'Migration artifact exists with unique timestamp 20261031021500');

  const migrationSql = fs.readFileSync(migrationPath, 'utf8');

  assert(
    migrationSql.includes('CREATE OR REPLACE FUNCTION public.get_reference_datasets_summary()'),
    'Defines function public.get_reference_datasets_summary() with zero caller parameters'
  );
  assert(
    migrationSql.includes('SECURITY DEFINER'),
    'Function is marked SECURITY DEFINER'
  );
  assert(
    migrationSql.includes('STABLE'),
    'Function is declared STABLE'
  );
  assert(
    migrationSql.includes('statement_timestamp()'),
    'Uses statement_timestamp() matching STABLE volatility'
  );
  assert(
    migrationSql.includes('SET search_path = pg_catalog, public, pg_temp'),
    'Hardened search_path prioritizes pg_catalog, public, pg_temp'
  );
  assert(
    migrationSql.includes('v_caller_id := auth.uid()') && migrationSql.includes('v_caller_id IS NULL'),
    'Guarded against unauthenticated callers (v_caller_id := auth.uid(); v_caller_id IS NULL)'
  );
  assert(
    migrationSql.includes('v_caller_role := public.get_user_role()') &&
    migrationSql.includes("v_caller_role IS DISTINCT FROM 'super_admin'"),
    'Role check uses NULL-safe v_caller_role IS DISTINCT FROM super_admin'
  );
  assert(
    migrationSql.includes('v_caller_approved := public.is_approved()') &&
    migrationSql.includes('v_caller_approved IS DISTINCT FROM true'),
    'Approval check uses NULL-safe v_caller_approved IS DISTINCT FROM true'
  );
  assert(
    migrationSql.includes('REVOKE ALL ON FUNCTION public.get_reference_datasets_summary() FROM PUBLIC;'),
    'Explicitly revokes execution from PUBLIC'
  );
  assert(
    migrationSql.includes('REVOKE ALL ON FUNCTION public.get_reference_datasets_summary() FROM anon;'),
    'Explicitly revokes execution from anon'
  );
  assert(
    migrationSql.includes('GRANT EXECUTE ON FUNCTION public.get_reference_datasets_summary() TO authenticated;'),
    'Explicitly grants execution strictly to authenticated sessions'
  );
  assert(
    migrationSql.includes('ORDER BY distinct_techniques DESC, tactic ASC'),
    'Deterministic Top 5 ordering enforced inside jsonb_agg for tactics'
  );
  assert(
    migrationSql.includes('ORDER BY distinct_techniques DESC, platform ASC'),
    'Deterministic Top 5 ordering enforced inside jsonb_agg for platforms'
  );
  assert(
    migrationSql.includes('COUNT(DISTINCT strat_name) = 1 THEN MIN(strat_name)') &&
    migrationSql.includes('ELSE NULL'),
    'SOC Analyst Top 5 strategies: returns NULL if descriptive name is missing or conflicting'
  );
  assert(
    migrationSql.includes('COUNT(DISTINCT mit_name) = 1 THEN MIN(mit_name)') &&
    migrationSql.includes('ELSE NULL'),
    'Security Engineer and IT Operations Top 5: returns NULL if mitigation name is missing or conflicting'
  );
  assert(
    migrationSql.includes('log_source_key') && migrationSql.includes('MIN(raw_log_source) AS log_source'),
    'SOC Analyst log source grouping normalizes case-insensitively with deterministic label'
  );
  assert(
    migrationSql.includes('mitigation_mapping_buckets'),
    'Calculates mitigation mapping buckets (zero, one, two, three_plus)'
  );
  assert(
    !migrationSql.includes('public.alerts') && !migrationSql.includes('public.alert_notes') && !migrationSql.includes('public.incident_tasks'),
    'Does not query private operational alerts, incident tasks, or investigation notes'
  );

  // Verify all 7 unnesting sites use unambiguous C-escaped regex E'[,;|\r\n]+'
  const delimiterLiteral = "E'[,;|\\r\\n]+'";
  const lateralUnnestMatches = migrationSql
    .split('\n')
    .filter((line) => line.includes('regexp_split_to_table') && line.includes(delimiterLiteral));
  assert(
    lateralUnnestMatches.length === 7,
    `All 7 lateral unnesting sites use explicit C-escaped regex E'[,;|\\r\\n]+' (found ${lateralUnnestMatches.length}/7)`
  );
  assert(
    !migrationSql.includes("'[,;|\\n]+'"),
    "Legacy un-escaped regex '[,;|\\n]+' is completely removed from migration"
  );

  // =========================================================================
  // Group 2: Strict ISO 8601 Timestamp Validation Tests
  // =========================================================================
  console.log('\n-- Group 2: Strict ISO 8601 Timestamp Validation Tests --');

  // Valid timestamps
  assert(isValidIso8601Timestamp('2026-10-31T02:15:00.000Z'), 'Accepts valid UTC timestamp ending in Z');
  assert(isValidIso8601Timestamp('2026-10-31T02:15:00+02:00'), 'Accepts valid timestamp with positive timezone offset (+02:00)');
  assert(isValidIso8601Timestamp('2026-10-31T02:15:00-05:00'), 'Accepts valid timestamp with negative timezone offset (-05:00)');
  assert(isValidIso8601Timestamp('2026-10-31T02:15:00.123456+00:00'), 'Accepts PostgreSQL statement_timestamp() representation with microsecond precision');

  // Rejections
  assert(!isValidIso8601Timestamp('2026-10-31'), 'Rejects date-only string (2026-10-31)');
  assert(!isValidIso8601Timestamp('10/31/2026, 2:15:00 AM'), 'Rejects locale-formatted date string');
  assert(!isValidIso8601Timestamp('October 31, 2026 02:15:00 UTC'), 'Rejects non-ISO parseable date string (October 31, 2026...)');
  assert(!isValidIso8601Timestamp('2026/10/31 02:15:00'), 'Rejects slash-delimited date-time string');
  assert(!isValidIso8601Timestamp('2026-02-30T10:00:00Z'), 'Rejects invalid calendar date (February 30th)');
  assert(!isValidIso8601Timestamp('2026-04-31T10:00:00Z'), 'Rejects invalid calendar date (April 31st)');
  assert(!isValidIso8601Timestamp('2026-02-29T10:00:00Z'), 'Rejects February 29th on non-leap year (2026)');
  assert(isValidIso8601Timestamp('2024-02-29T10:00:00Z'), 'Accepts February 29th on leap year (2024)');
  assert(!isValidIso8601Timestamp(''), 'Rejects empty timestamp string');
  assert(!isValidIso8601Timestamp('   '), 'Rejects whitespace-only timestamp string');
  assert(!isValidIso8601Timestamp(null), 'Rejects null timestamp');
  assert(!isValidIso8601Timestamp(123456789), 'Rejects numeric timestamp');

  // =========================================================================
  // Group 3: Typed Response Contract & Invariant Validation
  // =========================================================================
  console.log('\n-- Group 3: Typed Response Contract & Invariant Validation --');

  const validPayloadFixture: ReferenceDatasetsSummaryResponse = {
    summary_generated_at: '2026-10-31T02:15:00.000Z',
    soc_analyst: {
      total_rows: 652,
      distinct_techniques: 203,
      distinct_detection_strategies: 203,
      distinct_analytics: 189,
      distinct_data_components: 94,
      distinct_log_sources: 42,
      top_5_techniques_by_tactic: [{ tactic: 'Defense Evasion', techniques: 68 }],
      top_5_analytics_by_log_source: [{ log_source: 'Process: Process Creation', analytics: 84 }],
      top_5_techniques_by_platform: [{ platform: 'Windows', techniques: 142 }],
      top_5_detection_strategies_by_techniques: [
        {
          detection_strategy_attack_id: 'DET001',
          detection_strategy_name: 'Process Injection Detection',
          techniques: 14,
        },
      ],
    },
    security_engineer: {
      total_rows: 1559,
      distinct_techniques: 697,
      distinct_mitigations: 43,
      distinct_tactics: 14,
      distinct_platforms: 11,
      mitigated_techniques_count: 586,
      unmitigated_techniques_count: 111,
      mitigation_coverage_pct: 84.1,
      mitigation_mapping_buckets: {
        zero_mitigations: 111,
        one_mitigation: 248,
        two_mitigations: 182,
        three_plus_mitigations: 156,
      },
      top_5_mitigations_by_techniques: [
        {
          mitigation_id: 'M1038',
          mitigation_name: 'Execution Prevention',
          techniques: 112,
        },
      ],
      top_5_techniques_by_tactic: [{ tactic: 'Defense Evasion', techniques: 184 }],
      top_5_techniques_by_platform: [{ platform: 'Windows', techniques: 412 }],
    },
    it_operations: {
      total_rows: 1448,
      distinct_techniques: 586,
      distinct_tactics: 14,
      distinct_mitigations: 41,
      distinct_platforms: 10,
      top_5_platforms_by_techniques: [{ platform: 'Windows', techniques: 384 }],
      top_5_tactics_by_techniques: [{ tactic: 'Defense Evasion', techniques: 162 }],
      top_5_mitigations_by_techniques: [
        {
          mitigation_id: 'M1038',
          mitigation_name: 'Execution Prevention',
          techniques: 98,
        },
      ],
      mitigation_mapping_buckets: {
        zero_mitigations: 0,
        one_mitigation: 218,
        two_mitigations: 194,
        three_plus_mitigations: 174,
      },
    },
  };

  const validated = validateReferenceDatasetsSummary(validPayloadFixture);
  assert(validated !== null, 'Valid payload passes runtime schema validation');
  assert(validated.soc_analyst.distinct_techniques === 203, 'SOC Analyst distinct techniques is 203');
  assert(validated.security_engineer.distinct_techniques === 697, 'Security Engineer distinct techniques is 697');
  assert(validated.it_operations.distinct_techniques === 586, 'IT Operations distinct techniques is 586');

  // Invariant 1: total = mitigated + unmitigated
  const sec = validated.security_engineer;
  assert(
    sec.distinct_techniques === sec.mitigated_techniques_count + sec.unmitigated_techniques_count,
    'Mitigation partition invariant holds: 697 === 586 + 111'
  );

  // Invariant 2: buckets sum = total
  const secBuckets = sec.mitigation_mapping_buckets;
  const secBucketSum =
    secBuckets.zero_mitigations +
    secBuckets.one_mitigation +
    secBuckets.two_mitigations +
    secBuckets.three_plus_mitigations;
  assert(
    secBucketSum === sec.distinct_techniques,
    'Security Engineer mitigation buckets partition technique domain: 111 + 248 + 182 + 156 === 697'
  );

  const it = validated.it_operations;
  const itBuckets = it.mitigation_mapping_buckets;
  const itBucketSum =
    itBuckets.zero_mitigations +
    itBuckets.one_mitigation +
    itBuckets.two_mitigations +
    itBuckets.three_plus_mitigations;
  assert(
    itBucketSum === it.distinct_techniques,
    'IT Operations mitigation buckets partition technique domain: 0 + 218 + 194 + 174 === 586'
  );

  // Invariant 3: percentage consistency
  const expectedRatio = (sec.mitigated_techniques_count / sec.distinct_techniques) * 100;
  assert(
    Math.abs(sec.mitigation_coverage_pct - expectedRatio) <= 0.15,
    'Mitigation coverage percentage (84.1%) agrees with ratio (84.07%)'
  );

  // =========================================================================
  // Group 4: Nullable Descriptive Labels Tests
  // =========================================================================
  console.log('\n-- Group 4: Nullable Descriptive Labels Tests --');

  // Test nullable descriptive names when missing/conflicting
  const nullNamesPayload = JSON.parse(JSON.stringify(validPayloadFixture));
  nullNamesPayload.soc_analyst.top_5_detection_strategies_by_techniques[0].detection_strategy_name = null;
  nullNamesPayload.security_engineer.top_5_mitigations_by_techniques[0].mitigation_name = null;
  nullNamesPayload.it_operations.top_5_mitigations_by_techniques[0].mitigation_name = null;

  const validatedNullNames = validateReferenceDatasetsSummary(nullNamesPayload);
  assert(
    validatedNullNames.soc_analyst.top_5_detection_strategies_by_techniques[0].detection_strategy_name === null,
    'Accepts null detection_strategy_name when descriptive name is absent or conflicting'
  );
  assert(
    validatedNullNames.soc_analyst.top_5_detection_strategies_by_techniques[0].detection_strategy_attack_id === 'DET001',
    'Stable ID detection_strategy_attack_id remains present and intact when name is null'
  );
  assert(
    validatedNullNames.security_engineer.top_5_mitigations_by_techniques[0].mitigation_name === null,
    'Accepts null mitigation_name in Security Engineer when descriptive name is absent or conflicting'
  );
  assert(
    validatedNullNames.security_engineer.top_5_mitigations_by_techniques[0].mitigation_id === 'M1038',
    'Stable ID mitigation_id remains present and intact in Security Engineer when name is null'
  );
  assert(
    validatedNullNames.it_operations.top_5_mitigations_by_techniques[0].mitigation_name === null,
    'Accepts null mitigation_name in IT Operations when descriptive name is absent or conflicting'
  );
  assert(
    validatedNullNames.it_operations.top_5_mitigations_by_techniques[0].mitigation_id === 'M1038',
    'Stable ID mitigation_id remains present and intact in IT Operations when name is null'
  );

  // Reject empty string or whitespace-only descriptive name
  function expectValidationFailure(invalidData: unknown, testName: string) {
    let caught = false;
    try {
      validateReferenceDatasetsSummary(invalidData);
    } catch {
      caught = true;
    }
    assert(caught, testName);
  }

  const emptyStratName = JSON.parse(JSON.stringify(validPayloadFixture));
  emptyStratName.soc_analyst.top_5_detection_strategies_by_techniques[0].detection_strategy_name = '';
  expectValidationFailure(emptyStratName, 'Rejects empty string detection_strategy_name (must be null or trimmed non-empty)');

  const whitespaceStratName = JSON.parse(JSON.stringify(validPayloadFixture));
  whitespaceStratName.soc_analyst.top_5_detection_strategies_by_techniques[0].detection_strategy_name = '   ';
  expectValidationFailure(whitespaceStratName, 'Rejects whitespace-only detection_strategy_name');

  const emptyMitName = JSON.parse(JSON.stringify(validPayloadFixture));
  emptyMitName.security_engineer.top_5_mitigations_by_techniques[0].mitigation_name = '';
  expectValidationFailure(emptyMitName, 'Rejects empty string mitigation_name in Security Engineer');

  // =========================================================================
  // Group 5: Numeric Edge Cases & Mitigation Buckets Validation
  // =========================================================================
  console.log('\n-- Group 5: Numeric Edge Cases & Mitigation Buckets Validation --');

  // Test numeric validation: NaN, Infinity, -Infinity, negative, fractional
  const nanPayload = JSON.parse(JSON.stringify(validPayloadFixture));
  nanPayload.soc_analyst.total_rows = NaN;
  expectValidationFailure(nanPayload, 'Rejects NaN in total_rows');

  const posInfPayload = JSON.parse(JSON.stringify(validPayloadFixture));
  posInfPayload.soc_analyst.total_rows = Infinity;
  expectValidationFailure(posInfPayload, 'Rejects positive Infinity in total_rows');

  const negInfPayload = JSON.parse(JSON.stringify(validPayloadFixture));
  negInfPayload.soc_analyst.total_rows = -Infinity;
  expectValidationFailure(negInfPayload, 'Rejects negative Infinity in total_rows');

  const negativePayload = JSON.parse(JSON.stringify(validPayloadFixture));
  negativePayload.soc_analyst.total_rows = -1;
  expectValidationFailure(negativePayload, 'Rejects negative count in total_rows');

  const fractionalPayload = JSON.parse(JSON.stringify(validPayloadFixture));
  fractionalPayload.soc_analyst.total_rows = 12.5;
  expectValidationFailure(fractionalPayload, 'Rejects fractional count in total_rows');

  // Missing each of the four bucket fields in Security Engineer
  const bucketKeys = ['zero_mitigations', 'one_mitigation', 'two_mitigations', 'three_plus_mitigations'] as const;
  for (const bKey of bucketKeys) {
    const missingSecBucket = JSON.parse(JSON.stringify(validPayloadFixture));
    delete missingSecBucket.security_engineer.mitigation_mapping_buckets[bKey];
    expectValidationFailure(missingSecBucket, `Security Engineer: Rejects missing bucket "${bKey}"`);
  }

  // Missing each of the four bucket fields in IT Operations
  for (const bKey of bucketKeys) {
    const missingItBucket = JSON.parse(JSON.stringify(validPayloadFixture));
    delete missingItBucket.it_operations.mitigation_mapping_buckets[bKey];
    expectValidationFailure(missingItBucket, `IT Operations: Rejects missing bucket "${bKey}"`);
  }

  // Negative bucket values
  const negativeSecBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  negativeSecBucket.security_engineer.mitigation_mapping_buckets.zero_mitigations = -5;
  expectValidationFailure(negativeSecBucket, 'Security Engineer: Rejects negative bucket count');

  const negativeItBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  negativeItBucket.it_operations.mitigation_mapping_buckets.one_mitigation = -1;
  expectValidationFailure(negativeItBucket, 'IT Operations: Rejects negative bucket count');

  // Fractional bucket values
  const fractionalSecBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  fractionalSecBucket.security_engineer.mitigation_mapping_buckets.zero_mitigations = 10.5;
  expectValidationFailure(fractionalSecBucket, 'Security Engineer: Rejects fractional bucket count');

  const fractionalItBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  fractionalItBucket.it_operations.mitigation_mapping_buckets.two_mitigations = 4.2;
  expectValidationFailure(fractionalItBucket, 'IT Operations: Rejects fractional bucket count');

  // Non-finite bucket values
  const nanBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  nanBucket.security_engineer.mitigation_mapping_buckets.zero_mitigations = NaN;
  expectValidationFailure(nanBucket, 'Security Engineer: Rejects NaN bucket count');

  const infBucket = JSON.parse(JSON.stringify(validPayloadFixture));
  infBucket.it_operations.mitigation_mapping_buckets.three_plus_mitigations = Infinity;
  expectValidationFailure(infBucket, 'IT Operations: Rejects Infinity bucket count');

  // Incorrect bucket totals (bucket sum !== distinct_techniques)
  const secBucketSumMismatch = JSON.parse(JSON.stringify(validPayloadFixture));
  secBucketSumMismatch.security_engineer.mitigation_mapping_buckets.zero_mitigations += 1;
  expectValidationFailure(secBucketSumMismatch, 'Security Engineer: Rejects payload with bucket sum mismatch');

  const itBucketSumMismatch = JSON.parse(JSON.stringify(validPayloadFixture));
  itBucketSumMismatch.it_operations.mitigation_mapping_buckets.one_mitigation += 5;
  expectValidationFailure(itBucketSumMismatch, 'IT Operations: Rejects payload with bucket sum mismatch');

  // =========================================================================
  // Group 6: Client-Side Authorization & Service Mock Isolation
  // =========================================================================
  console.log('\n-- Group 6: Client-Side Authorization & Service Mock Isolation --');

  const approvedSuperAdmin: UserProfile = {
    id: 'usr-admin-01',
    name: 'Sarah Lin',
    email: 'sarah.lin@platform.internal',
    role: 'super_admin',
    callsign: 'SYSADMIN-0',
    title: 'Platform Administrator',
    accountStatus: 'approved',
  };

  const pendingSuperAdmin: UserProfile = {
    ...approvedSuperAdmin,
    id: 'usr-admin-02',
    accountStatus: 'pending',
  };

  const approvedAnalyst: UserProfile = {
    id: 'usr-analyst-01',
    name: 'Alex Mercer',
    email: 'alex.mercer@soc.internal',
    role: 'soc_analyst',
    callsign: 'SPECTER-1',
    title: 'Senior Incident Analyst',
    accountStatus: 'approved',
  };

  const approvedEngineer: UserProfile = {
    id: 'usr-engineer-01',
    name: 'Elena Rostova',
    email: 'elena.rostova@soc.internal',
    role: 'security_engineer',
    callsign: 'SENTINEL-4',
    title: 'Detection Engineer',
    accountStatus: 'approved',
  };

  const approvedItOps: UserProfile = {
    id: 'usr-itops-01',
    name: 'Marcus Vance',
    email: 'marcus.vance@soc.internal',
    role: 'it_operations',
    callsign: 'RECOVERY-9',
    title: 'Lead Systems Administrator',
    accountStatus: 'approved',
  };

  // Test unauthorized users: verify AccessDeniedError AND verify mocked RPC count remains EXACTLY ZERO
  const unauthorizedUsers = [
    { label: 'Pending Super Admin', user: pendingSuperAdmin },
    { label: 'Approved SOC Analyst', user: approvedAnalyst },
    { label: 'Approved Security Engineer', user: approvedEngineer },
    { label: 'Approved IT Operations', user: approvedItOps },
  ];

  for (const { label, user } of unauthorizedUsers) {
    let mockRpcCallCount = 0;
    const trackingMockClient: AggregateRpcClient = {
      rpc: async () => {
        mockRpcCallCount++;
        return { data: validPayloadFixture, error: null };
      },
    };

    let caughtError = false;
    try {
      await fetchReferenceDatasetsSummary(user, trackingMockClient);
    } catch (err) {
      if (err instanceof AccessDeniedError) {
        caughtError = true;
      }
    }
    assert(caughtError, `${label} is rejected with AccessDeniedError`);
    assert(mockRpcCallCount === 0, `${label}: Mocked RPC call count remains strictly 0 (no RPC invoked)`);
  }

  // Test approved Super Admin: verify RPC is invoked exactly once, correct function name, and zero table queries
  let adminRpcCallCount = 0;
  let adminRpcFunctionName = '';
  let fromMethodCallCount = 0;

  const mockAdminClient: AggregateRpcClient & { from: () => void } = {
    rpc: async (fnName: string) => {
      adminRpcCallCount++;
      adminRpcFunctionName = fnName;
      return { data: validPayloadFixture, error: null };
    },
    from: () => {
      fromMethodCallCount++;
      throw new Error('Forbidden table access! Super Admin must strictly use the aggregate RPC.');
    },
  };

  const adminResult = await fetchReferenceDatasetsSummary(approvedSuperAdmin, mockAdminClient);
  assert(adminResult !== null, 'Service executes successfully for approved Super Admin');
  assert(adminRpcCallCount === 1, 'Mocked RPC was invoked exactly once for approved Super Admin');
  assert(adminRpcFunctionName === 'get_reference_datasets_summary', 'Exact RPC function name "get_reference_datasets_summary" was invoked');
  assert(fromMethodCallCount === 0, 'Zero direct table queries occurred (mock .from() call count is 0)');
  assert(adminResult.soc_analyst.distinct_techniques === 203, 'Returned payload contains correct aggregated data');

  // =========================================================================
  // Comprehensive RPC Execution Error Sanitization Tests
  // Covers failure paths:
  // 1. Supabase resolves with { error } containing raw DB details
  // 2. RPC Promise rejects with a raw network / TypeError failure
  // 3. RPC throws synchronously
  // 4. Removal of unsafe browser diagnostic logger runtime functions
  // =========================================================================

  // Test Failure Path 1: Database RPC error with raw internal details
  const representativeRawDbError = 'Database query timed out: internal relation or SQL details';
  const representativeDbCode = '57014';

  const errorMockClient: AggregateRpcClient = {
    rpc: async () => ({
      data: null,
      error: {
        message: representativeRawDbError,
        code: representativeDbCode,
        details: 'Relation public.soc_analyst_knowledge lock contention on pid 18239',
        hint: 'Retry transaction or inspect locks',
      },
    }),
  };

  let rpcFailedAndRejected = false;
  let receivedErrorMessage = '';
  let caughtErrorObj: unknown = null;

  try {
    await fetchReferenceDatasetsSummary(approvedSuperAdmin, errorMockClient);
  } catch (err) {
    rpcFailedAndRejected = true;
    caughtErrorObj = err;
    if (err instanceof Error) {
      receivedErrorMessage = err.message;
    }
  }

  assert(rpcFailedAndRejected, 'Failure Path 1: Failed RPC is rejected and throws an error');
  assert(caughtErrorObj instanceof Error, 'Failure Path 1: Rejected error is a proper Error instance');
  assert(
    receivedErrorMessage === SAFE_RPC_ERROR_MESSAGE,
    `Failure Path 1: Error received by caller is exactly the safe generic message: "${SAFE_RPC_ERROR_MESSAGE}"`
  );
  assert(
    !receivedErrorMessage.includes(representativeRawDbError),
    'Failure Path 1: Raw database error string is absent from user-facing error'
  );
  assert(
    !receivedErrorMessage.includes('internal relation or SQL details'),
    'Failure Path 1: Internal SQL details are absent from user-facing error'
  );
  assert(
    !receivedErrorMessage.includes('soc_analyst_knowledge'),
    'Failure Path 1: Internal table names are absent from user-facing error'
  );
  assert(
    !receivedErrorMessage.includes('57014'),
    'Failure Path 1: Internal error code is absent from user-facing error'
  );
  assert(
    (caughtErrorObj as any).cause === undefined,
    'Failure Path 1: Original exception is NOT leaked via Error.cause'
  );

  // Test Failure Path 2: RPC Promise rejects with raw network/connection failure
  const networkErrorString = 'TypeError: Failed to fetch: connect ECONNREFUSED 10.0.4.15:5432';
  const networkRejectClient: AggregateRpcClient = {
    rpc: async () => {
      throw new TypeError(networkErrorString);
    },
  };

  let networkRejected = false;
  let networkErrorMessage = '';
  let caughtNetworkErr: unknown = null;

  try {
    await fetchReferenceDatasetsSummary(approvedSuperAdmin, networkRejectClient);
  } catch (err) {
    networkRejected = true;
    caughtNetworkErr = err;
    if (err instanceof Error) {
      networkErrorMessage = err.message;
    }
  }

  assert(networkRejected, 'Failure Path 2: Rejected RPC Promise is caught and rejected');
  assert(caughtNetworkErr instanceof Error, 'Failure Path 2: Caught error is a proper Error instance');
  assert(
    networkErrorMessage === SAFE_RPC_ERROR_MESSAGE,
    'Failure Path 2: Network failure yields exactly the safe generic message'
  );
  assert(
    !networkErrorMessage.includes('Failed to fetch'),
    'Failure Path 2: Raw fetch failure is absent from user-facing error'
  );
  assert(
    !networkErrorMessage.includes('ECONNREFUSED'),
    'Failure Path 2: Connection details are absent from user-facing error'
  );
  assert(
    !networkErrorMessage.includes('10.0.4.15'),
    'Failure Path 2: Internal IP addresses are absent from user-facing error'
  );
  assert(
    (caughtNetworkErr as any).cause === undefined,
    'Failure Path 2: Original network error is NOT leaked via Error.cause'
  );

  // Test Failure Path 3: RPC throws synchronously
  const syncErrorString = 'Synchronous adapter crash: internal memory buffer allocation failed';
  const syncThrowClient: AggregateRpcClient = {
    rpc: () => {
      throw new Error(syncErrorString);
    },
  };

  let syncThrew = false;
  let syncErrorMessage = '';
  let caughtSyncErr: unknown = null;

  try {
    await fetchReferenceDatasetsSummary(approvedSuperAdmin, syncThrowClient);
  } catch (err) {
    syncThrew = true;
    caughtSyncErr = err;
    if (err instanceof Error) {
      syncErrorMessage = err.message;
    }
  }

  assert(syncThrew, 'Failure Path 3: Synchronous RPC exception is caught and rejected');
  assert(caughtSyncErr instanceof Error, 'Failure Path 3: Caught sync error is a proper Error instance');
  assert(
    syncErrorMessage === SAFE_RPC_ERROR_MESSAGE,
    'Failure Path 3: Synchronous throw yields exactly the safe generic message'
  );
  assert(
    !syncErrorMessage.includes('Synchronous adapter crash'),
    'Failure Path 3: Raw synchronous error is absent from user-facing error'
  );
  assert(
    !syncErrorMessage.includes('memory buffer'),
    'Failure Path 3: Internal memory details are absent from user-facing error'
  );
  assert(
    (caughtSyncErr as any).cause === undefined,
    'Failure Path 3: Original sync exception is NOT leaked via Error.cause'
  );

  // Architectural Isolation Notice on Client Initialization Failure Testing:
  // In `superAdminAggregateService.ts`, `createProductionAggregateRpcClient` is an unexported,
  // internal closure that directly invokes the statically imported `getSupabaseClient()`.
  // Calling `fetchReferenceDatasetsSummary(approvedSuperAdmin)` without a `clientOverride` would rely
  // on unconfigured environment variables to trigger the initialization failure path in `getSupabaseClient()`.
  // In an environment where valid Supabase credentials (VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY)
  // are configured, omitting `clientOverride` would attempt a live network request to Supabase.
  // Because isolating this initialization path deterministically without live network exposure
  // would require modifying production code (e.g. injecting a client factory or exporting adapter hooks),
  // which is strictly outside this test-only scope, the live-calling test is removed to guarantee
  // zero live database or network requests in all environments.

  // Test Failure Path 4: Removal of Unsafe Browser Diagnostic Logger Runtime Functions
  // In the browser client, raw diagnostic loggers provide an attack surface for intercepting raw database errors.
  // Verify that the unsafe diagnostic logger runtime functions are completely removed from service exports.
  assert(
    (superAdminAggregateModule as any).setDiagnosticLogger === undefined,
    'Failure Path 4: Unsafe setDiagnosticLogger runtime function is removed from service exports'
  );
  assert(
    (superAdminAggregateModule as any).getDiagnosticLogger === undefined,
    'Failure Path 4: Unsafe getDiagnosticLogger runtime function is removed from service exports'
  );

  // Test error handling: null payload from RPC
  const nullDataMockClient: AggregateRpcClient = {
    rpc: async () => ({
      data: null,
      error: null,
    }),
  };

  let caughtNullPayload = false;
  try {
    await fetchReferenceDatasetsSummary(approvedSuperAdmin, nullDataMockClient);
  } catch (err) {
    if (err instanceof Error && err.message.includes('RPC returned an empty or null payload')) {
      caughtNullPayload = true;
    }
  }
  assert(caughtNullPayload, 'Service properly rejects empty/null payloads returned from RPC');

  // =========================================================================
  // Group 7: Zero Raw Records & Role Isolation Invariant
  // =========================================================================
  console.log('\n-- Group 7: Zero Raw Records & Role Isolation Invariant --');

  const serialized = JSON.stringify(validPayloadFixture);
  assert(!serialized.includes('alert_id'), 'Zero alert_id fields in response contract');
  assert(!serialized.includes('note_text'), 'Zero note_text fields in response contract');
  assert(!serialized.includes('evidence'), 'Zero evidence fields in response contract');
  assert(!serialized.includes('working_hours'), 'Zero working_hours fields in response contract');
  assert(!serialized.includes('productivity'), 'Zero productivity fields in response contract');
  assert(!serialized.includes('incident_tasks'), 'Zero incident_tasks fields in response contract');

  // =========================================================================
  // Group 8: JavaScript-Side Multi-Value Delimiter Regression Tests
  // =========================================================================
  console.log('\n-- Group 8: JavaScript-Side Multi-Value Delimiter Regression Tests (Test Runtime Verification Only) --');

  // NOTE ON EXECUTION BOUNDARY:
  // These tests are JavaScript-side regression tests verifying string and regex splitting logic
  // within the Node.js test runtime. They do NOT execute PostgreSQL's regular-expression engine
  // and do NOT claim independent PostgreSQL behavior verification.
  const delimiterRegex = /[,;|\r\n]+/;

  function testSplit(input: string): string[] {
    return input
      .split(delimiterRegex)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !['none', 'null', 'n/a', 'unknown', 'undefined'].includes(s.toLowerCase()));
  }

  // Comma splitting
  const commaSplit = testSplit('Reconnaissance,Initial Access');
  assert(
    commaSplit.length === 2 && commaSplit[0] === 'Reconnaissance' && commaSplit[1] === 'Initial Access',
    'Splits comma-separated tokens cleanly in JavaScript test runtime'
  );

  // Semicolon splitting
  const semiSplit = testSplit('Execution;Persistence');
  assert(
    semiSplit.length === 2 && semiSplit[0] === 'Execution' && semiSplit[1] === 'Persistence',
    'Splits semicolon-separated tokens cleanly in JavaScript test runtime'
  );

  // Pipe splitting
  const pipeSplit = testSplit('Discovery|Lateral Movement');
  assert(
    pipeSplit.length === 2 && pipeSplit[0] === 'Discovery' && pipeSplit[1] === 'Lateral Movement',
    'Splits pipe-separated tokens cleanly in JavaScript test runtime'
  );

  // LF (\n) splitting
  const lfSplit = testSplit('Command and Control\nExfiltration');
  assert(
    lfSplit.length === 2 && lfSplit[0] === 'Command and Control' && lfSplit[1] === 'Exfiltration',
    'Splits LF (\\n) separated tokens cleanly in JavaScript test runtime'
  );

  // CRLF (\r\n) splitting: verifies no residual \r is left on preceding token
  const crlfSplit = testSplit('Defense Evasion\r\nCredential Access');
  assert(
    crlfSplit.length === 2 && crlfSplit[0] === 'Defense Evasion' && crlfSplit[1] === 'Credential Access',
    'Splits CRLF (\\r\\n) separated tokens cleanly in JavaScript test runtime'
  );
  assert(
    !crlfSplit[0].includes('\r') && !crlfSplit[1].includes('\r'),
    'CRLF split leaves zero residual \\r (carriage return 0x0D) characters on tokens in JavaScript test runtime'
  );

  // Multiple consecutive delimiters (e.g. comma + space + newline)
  const multiDelimSplit = testSplit('Initial Access, \r\n; || Execution');
  assert(
    multiDelimSplit.length === 2 && multiDelimSplit[0] === 'Initial Access' && multiDelimSplit[1] === 'Execution',
    'Consumes consecutive mixed delimiters as a single delimiter boundary in JavaScript test runtime'
  );

  // Integrity of words containing the letter 'n' (CRITICAL)
  // Words like 'Reconnaissance', 'Windows', 'Containers', 'Execution', 'Persistence', 'Credential Access', 'Defense Evasion'
  const wordsWithN = [
    'Reconnaissance',
    'Windows',
    'Containers',
    'Execution',
    'Persistence',
    'Credential Access',
    'Defense Evasion',
    'Network',
  ];
  for (const word of wordsWithN) {
    const singleWordSplit = testSplit(word);
    assert(
      singleWordSplit.length === 1 && singleWordSplit[0] === word,
      `Word "${word}" containing letter 'n' is never split on 'n' in JavaScript test runtime`
    );
  }

  // Composite multi-delimiter list with words containing 'n'
  const compositeInput = 'Windows, Linux; macOS | Containers\nKubernetes\r\nNetwork';
  const compositeResult = testSplit(compositeInput);
  assert(
    compositeResult.length === 6 &&
    compositeResult[0] === 'Windows' &&
    compositeResult[1] === 'Linux' &&
    compositeResult[2] === 'macOS' &&
    compositeResult[3] === 'Containers' &&
    compositeResult[4] === 'Kubernetes' &&
    compositeResult[5] === 'Network',
    'Complex composite input splits cleanly into all 6 platform tokens with words containing letter "n" intact in JavaScript test runtime'
  );

  console.log('\n=== ALL SUPER ADMIN AGGREGATE RPC FOUNDATION TESTS PASSED ===');
}

runSuperAdminAggregateRpcTests().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
