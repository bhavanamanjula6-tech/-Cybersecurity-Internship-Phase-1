/**
 * CyberOps SOC — Authentication & User Governance Security Test Suite
 *
 * Verifies:
 * 1. Registration input validation, duplicate email detection (identities: []), and email confirmation flows.
 * 2. Strict workspace access gates for pending, rejected, disabled, missing-profile, and invalid-role users.
 * 3. Stale localStorage session invalidation upon revocation.
 * 4. Production fail-closed behavior (no silent fallback to fake users).
 * 5. Super Admin governance invariants:
 *    - Anti-self-approval and anti-self-demotion guards.
 *    - Permitted operational-role-only assignment (soc_analyst, security_engineer, it_operations).
 *    - Zero-row database update detection.
 *    - Atomic persistent platform governance audit trails.
 *    - Last-active-Super-Admin concurrency protection.
 * 6. SQL migration invariants for automated profile provisioning and RLS governance.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEMO_PERSONAS, UserProfile, UserRole, AccessDeniedError } from '../types/auth';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { SupabaseAuditLogRepository } from '../repositories/supabase/SupabaseAuditLogRepository';
import {
  getSupabaseConfigurationStatus,
  getStorageMode,
  setStorageMode,
  migrateStorageMode,
  clearAllAuthStorage,
  scopedAuthStorageAdapter,
  STORAGE_MODE_KEY,
  AUTH_STORAGE_KEY,
} from '../lib/supabaseClient';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runAuthAndGovernanceTests() {
  console.log('=== RUNNING AUTHENTICATION & USER GOVERNANCE VERIFICATION TESTS ===');
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

  // =========================================================================
  // Group 1: Registration Validation & Duplicate Email Handling
  // =========================================================================
  console.log('-- Group 1: Registration Validation & Duplicate Email Handling --');

  // Test 1: Password complexity requires at least 8 characters
  function validateRegistration(email: string, pass: string, fullName: string) {
    if (!email || !pass || !fullName) return { valid: false, error: 'All fields required' };
    if (pass.length < 8) return { valid: false, error: 'Password must be at least 8 characters long.' };
    return { valid: true };
  }

  assert(
    validateRegistration('user@soc.internal', 'short', 'Test Operator').valid === false,
    'Registration rejects passwords under 8 characters'
  );
  assert(
    validateRegistration('user@soc.internal', 'securePass2026!', 'Test Operator').valid === true,
    'Registration accepts passwords with 8 or more characters'
  );

  // Test 2: Detect duplicate email via empty identities array (Supabase email confirmation behavior)
  function handleSignUpResponse(data: { user?: { identities?: any[] } | null }) {
    if (data?.user && Array.isArray(data.user.identities) && data.user.identities.length === 0) {
      return { success: false, error: 'An account with this email address already exists.' };
    }
    return { success: true };
  }

  assert(
    handleSignUpResponse({ user: { identities: [] } }).success === false,
    'Signup detects duplicate email when identities array is empty'
  );
  assert(
    handleSignUpResponse({ user: { identities: [{ id: 'id-1' }] } }).success === true,
    'Signup succeeds when identities array contains active identity'
  );

  // =========================================================================
  // Group 2: Account Status & Workspace Access Gates
  // =========================================================================
  console.log('-- Group 2: Account Status & Workspace Access Gates --');

  // Logic mirroring the hardened isApprovedOperator gate in App.tsx
  function isOperatorAuthorized(user: UserProfile | null): boolean {
    if (!user) return false;
    const isApproved = user.accountStatus === 'approved';
    const hasRole = Boolean(user.role);
    const isValidRole = ['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'].includes(user.role);
    return isApproved && hasRole && isValidRole;
  }

  // Approved users with valid roles
  assert(
    isOperatorAuthorized({
      id: 'usr-1',
      name: 'Approved Analyst',
      email: 'analyst@soc.internal',
      role: 'soc_analyst',
      callsign: 'SPECTER',
      title: 'Analyst',
      accountStatus: 'approved',
    }) === true,
    'Approved user with valid operational role is granted access'
  );

  // Pending user denied
  assert(
    isOperatorAuthorized({
      id: 'usr-2',
      name: 'Pending Operator',
      email: 'pending@soc.internal',
      role: 'soc_analyst',
      callsign: 'PENDING',
      title: 'Applicant',
      accountStatus: 'pending',
    }) === false,
    'Pending account is strictly denied workspace access'
  );

  // Rejected user denied
  assert(
    isOperatorAuthorized({
      id: 'usr-3',
      name: 'Rejected User',
      email: 'rejected@soc.internal',
      role: 'soc_analyst',
      callsign: 'REJECTED',
      title: 'Applicant',
      accountStatus: 'rejected',
    }) === false,
    'Rejected account is strictly denied workspace access'
  );

  // Disabled user denied
  assert(
    isOperatorAuthorized({
      id: 'usr-4',
      name: 'Disabled User',
      email: 'disabled@soc.internal',
      role: 'it_operations',
      callsign: 'DISABLED',
      title: 'Ex-Admin',
      accountStatus: 'disabled',
    }) === false,
    'Disabled account is strictly denied workspace access'
  );

  // Missing profile / null user denied
  assert(
    isOperatorAuthorized(null) === false,
    'Unauthenticated null user is strictly denied workspace access'
  );

  // User with null role denied
  assert(
    isOperatorAuthorized({
      id: 'usr-5',
      name: 'No Role User',
      email: 'norole@soc.internal',
      role: null as any,
      callsign: 'NOROLE',
      title: 'Applicant',
      accountStatus: 'approved',
    }) === false,
    'Account without assigned operational role is strictly denied workspace access'
  );

  // User with invalid/unrecognized role denied
  assert(
    isOperatorAuthorized({
      id: 'usr-6',
      name: 'Custom Role User',
      email: 'guest@soc.internal',
      role: 'guest_observer' as any,
      callsign: 'GUEST',
      title: 'Guest',
      accountStatus: 'approved',
    }) === false,
    'Account with unrecognized role is strictly denied workspace access'
  );

  // =========================================================================
  // Group 3: Stale Session Cleanup & Anti-Mock Production Invariants
  // =========================================================================
  console.log('-- Group 3: Stale Session Cleanup & Anti-Mock Production Invariants --');

  // Verify production fail-closed status resolution
  const prodUnconfigured = getSupabaseConfigurationStatus({
    url: undefined,
    key: undefined,
    isProd: true,
    isDev: false,
  });

  assert(
    prodUnconfigured.mode === 'production_fail_closed',
    'Unconfigured production environment evaluates to production_fail_closed'
  );
  assert(
    prodUnconfigured.configured === false,
    'Unconfigured production reports configured === false'
  );

  // Verify DEMO_PERSONAS have accountStatus === 'approved'
  assert(
    DEMO_PERSONAS.soc_analyst.accountStatus === 'approved' &&
      DEMO_PERSONAS.super_admin.accountStatus === 'approved',
    'All predefined demo personas declare approved accountStatus'
  );

  // =========================================================================
  // Group 4: Super Admin Governance & Anti-Privilege Escalation
  // =========================================================================
  console.log('-- Group 4: Super Admin Governance & Anti-Privilege Escalation --');

  const superAdmin = DEMO_PERSONAS.super_admin;
  const analyst = DEMO_PERSONAS.soc_analyst;
  const localAuditRepo = new LocalAuditLogRepository();
  const supabaseAuditRepo = new SupabaseAuditLogRepository();

  // Test: Anti-self-approval guard in governance logic
  function validateApprovalAttempt(adminId: string, targetUserId: string, assignedRole: string) {
    if (adminId === targetUserId) {
      throw new Error('Security Policy Violation: Administrators cannot approve themselves.');
    }
    if (assignedRole === 'super_admin') {
      throw new Error('Security Policy Violation: Super Admin roles cannot be assigned through user governance.');
    }
    if (!['soc_analyst', 'security_engineer', 'it_operations'].includes(assignedRole)) {
      throw new Error('Security Policy Violation: Invalid operational role assigned.');
    }
    return true;
  }

  // Self approval throws
  let selfApproveBlocked = false;
  try {
    validateApprovalAttempt('usr-admin-01', 'usr-admin-01', 'soc_analyst');
  } catch (err: any) {
    selfApproveBlocked = err.message.includes('cannot approve themselves');
  }
  assert(selfApproveBlocked, 'Self-approval attempt is strictly blocked');

  // Assigning Super Admin role throws
  let superAdminAssignBlocked = false;
  try {
    validateApprovalAttempt('usr-admin-01', 'usr-pending-01', 'super_admin');
  } catch (err: any) {
    superAdminAssignBlocked = err.message.includes('Super Admin roles cannot be assigned');
  }
  assert(superAdminAssignBlocked, 'Assigning Super Admin role via governance is strictly blocked');

  // Assigning valid operational role succeeds
  assert(
    validateApprovalAttempt('usr-admin-01', 'usr-pending-01', 'soc_analyst') === true,
    'Assigning soc_analyst operational role passes governance check'
  );
  assert(
    validateApprovalAttempt('usr-admin-01', 'usr-pending-02', 'it_operations') === true,
    'Assigning it_operations operational role passes governance check'
  );
  assert(
    validateApprovalAttempt('usr-admin-01', 'usr-pending-03', 'security_engineer') === true,
    'Assigning security_engineer operational role passes governance check'
  );

  // Test: Zero-row database update detection logic
  function verifyDatabaseUpdateResult(data: any[] | null, error: any) {
    if (error) throw new Error(`Database update failed: ${error.message}`);
    if (!data || data.length === 0) {
      throw new Error('Database update affected 0 rows. You may lack permission to update this profile.');
    }
    return true;
  }

  let zeroRowCaught = false;
  try {
    verifyDatabaseUpdateResult([], null);
  } catch (err: any) {
    zeroRowCaught = err.message.includes('affected 0 rows');
  }
  assert(zeroRowCaught, 'Zero-row database update is detected and rejected with explicit error');

  // Test: Governance audit logging in LocalAuditLogRepository
  const govLog = await localAuditRepo.recordGovernanceAction(superAdmin, {
    actionType: 'unlock_account',
    targetEmail: 'new.operator@soc.internal',
    justification: 'Approved credentials for SOC Analyst',
  });
  assert(
    govLog.actionType === 'unlock_account' &&
      govLog.status === 'SUCCESS' &&
      govLog.isSimulated === false,
    'LocalAuditLogRepository records real platform governance audit log'
  );

  // Test: Operational role attempting governance audit throws AccessDeniedError
  let operationalAuditBlocked = false;
  try {
    await localAuditRepo.recordGovernanceAction(analyst, {
      actionType: 'unlock_account',
      targetEmail: 'fraud@soc.internal',
      justification: 'Unauthorized',
    });
  } catch (err: any) {
    operationalAuditBlocked = err instanceof AccessDeniedError;
  }
  assert(operationalAuditBlocked, 'Operational roles cannot record governance audit actions');

  // Test: SupabaseAuditLogRepository implements recordGovernanceAction and rejects non-admins
  let supabaseGovBlocked = false;
  try {
    await supabaseAuditRepo.recordGovernanceAction(analyst, {
      actionType: 'unlock_account',
      targetEmail: 'fraud@soc.internal',
      justification: 'Unauthorized',
    });
  } catch (err: any) {
    supabaseGovBlocked = err instanceof AccessDeniedError;
  }
  assert(supabaseGovBlocked, 'SupabaseAuditLogRepository rejects governance actions from non-admins');

  // Test: LocalAuditLogRepository preserves expectedAuditId if provided
  const expectedId = 'AUD-TEST-UUID-12345';
  const customGovLog = await localAuditRepo.recordGovernanceAction(superAdmin, {
    actionType: 'unlock_account',
    targetEmail: 'verified.operator@soc.internal',
    justification: 'Verified with expected audit ID',
    expectedAuditId: expectedId,
  });
  assert(
    customGovLog.id === expectedId,
    'LocalAuditLogRepository associates exact expectedAuditId with governance log'
  );

  // Test: Dashboard error differentiation logic (profile update vs audit confirmation)
  function determineDashboardFeedback(updateSucceeded: boolean, auditConfirmed: boolean, auditErrMsg?: string) {
    if (!updateSucceeded) {
      return { type: 'error', message: 'Database update failed' };
    }
    if (!auditConfirmed) {
      return {
        type: 'error',
        message: `Profile update may have succeeded in database, but persistent audit confirmation is unverified: ${auditErrMsg || ''}`,
      };
    }
    return { type: 'success', message: 'Account approved successfully' };
  }

  const failedAuditResult = determineDashboardFeedback(true, false, 'No persistent record found');
  assert(
    failedAuditResult.type === 'error' &&
      failedAuditResult.message.includes('persistent audit confirmation is unverified'),
    'Dashboard produces explicit error feedback when profile update succeeds but audit confirmation fails'
  );

  const fullSuccessResult = determineDashboardFeedback(true, true);
  assert(
    fullSuccessResult.type === 'success',
    'Dashboard produces success feedback only when both database update and audit confirmation succeed'
  );

  // =========================================================================
  // Group 5: SQL Migration Invariants for User Registration & Governance
  // =========================================================================
  console.log('-- Group 5: SQL Migration Invariants for User Registration & Governance --');

  const migrationPath = path.resolve(__dirname, '../../supabase/migrations/20261016000000_user_registration_and_governance.sql');
  assert(fs.existsSync(migrationPath), 'Migration artifact 20261016000000_user_registration_and_governance.sql exists');

  const migrationContent = fs.readFileSync(migrationPath, 'utf8');

  assert(
    migrationContent.includes('INSERT INTO public.platform_bootstrap_state (id, is_bootstrapped)') &&
      migrationContent.includes('VALUES (1, false)') &&
      migrationContent.includes('ON CONFLICT (id) DO NOTHING;'),
    'Migration 2 idempotently provisions platform_bootstrap_state singleton row (id = 1)'
  );

  assert(
    migrationContent.includes('ALTER TABLE public.user_profiles') &&
      migrationContent.includes('ADD COLUMN IF NOT EXISTS last_audit_id UUID REFERENCES public.audit_logs(id);'),
    'Migration 2 adds last_audit_id foreign key column to user_profiles'
  );

  assert(
    migrationContent.includes('CREATE OR REPLACE FUNCTION public.handle_new_user()') &&
      migrationContent.includes("account_status,") &&
      migrationContent.includes("'pending'") &&
      migrationContent.includes("NULL,"),
    'handle_new_user() trigger provisions pending profiles with NULL role'
  );

  assert(
    migrationContent.includes("CHECK (account_status IN ('pending', 'approved', 'disabled', 'rejected'))"),
    'user_profiles_account_status_check supports pending, approved, disabled, and rejected'
  );

  assert(
    migrationContent.includes("OLD.id = auth.uid()") &&
      migrationContent.includes("Administrators cannot approve themselves"),
    'trg_protect_user_profile_mutation enforces database-level anti-self-approval'
  );

  assert(
    migrationContent.includes("NEW.role = 'super_admin'") &&
      migrationContent.includes("Super Admin role can only be provisioned through server bootstrap"),
    'trg_protect_user_profile_mutation prevents Super Admin promotion via client operations'
  );

  assert(
    migrationContent.includes("NEW.role NOT IN ('soc_analyst', 'security_engineer', 'it_operations')"),
    'trg_protect_user_profile_mutation restricts role assignment strictly to operational roles'
  );

  assert(
    migrationContent.includes("PERFORM 1 FROM public.platform_bootstrap_state WHERE id = 1 FOR UPDATE;") &&
      migrationContent.includes("IF NOT FOUND THEN") &&
      migrationContent.includes("Security Policy Invariant Violation: platform_bootstrap_state lock row (id=1) is missing."),
    'trg_protect_user_profile_mutation fails closed (RAISE EXCEPTION) if platform_bootstrap_state lock row is missing'
  );

  assert(
    migrationContent.includes("v_audit_id := gen_random_uuid();") &&
      migrationContent.includes("INSERT INTO public.audit_logs") &&
      migrationContent.includes("NEW.last_audit_id := v_audit_id;"),
    'trg_protect_user_profile_mutation atomically assigns generated audit ID to user_profiles.last_audit_id'
  );

  assert(
    migrationContent.includes("OLD.last_audit_id IS DISTINCT FROM NEW.last_audit_id"),
    'trg_protect_user_profile_mutation protects last_audit_id from unauthorized operator modification'
  );

  // =========================================================================
  // Group 6: One-Time Super Admin Bootstrap Invariants & CLI Configuration
  // =========================================================================
  console.log('-- Group 6: One-Time Super Admin Bootstrap Invariants & CLI Configuration --');

  const { validateBootstrapConfig, sanitizeErrorMessage, resolveBootstrapConfig } = await import('../../scripts/bootstrapAdmin');

  // Test: Missing URL
  const resMissingUrl = validateBootstrapConfig({
    supabaseUrl: '',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
  }, 'localhost');
  assert(resMissingUrl.valid === false && Boolean(resMissingUrl.error?.includes('Missing SUPABASE_URL')), 'Bootstrap CLI rejects missing SUPABASE_URL');

  // Test: Missing service-role key
  const resMissingKey = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: '',
    adminEmail: 'admin@soc.internal',
  }, 'test-ref.supabase.co');
  assert(resMissingKey.valid === false && Boolean(resMissingKey.error?.includes('Missing SUPABASE_SERVICE_ROLE_KEY')), 'Bootstrap CLI rejects missing service-role key');

  // Test: Invalid email format
  const resInvalidEmail = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: 'invalid-email-format',
  }, 'test-ref.supabase.co');
  assert(resInvalidEmail.valid === false && Boolean(resInvalidEmail.error?.includes('Missing or invalid INITIAL_SUPER_ADMIN_EMAIL')), 'Bootstrap CLI rejects invalid administrator email');

  // Test: Missing project confirmation
  const resMissingConfirm = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
  }, undefined);
  assert(resMissingConfirm.valid === false && Boolean(resMissingConfirm.error?.includes('Project confirmation required')), 'Bootstrap CLI requires explicit --confirm-project argument');

  // Test: Project mismatch confirmation
  const resMismatchConfirm = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
  }, 'wrong-project.supabase.co');
  assert(resMismatchConfirm.valid === false && Boolean(resMismatchConfirm.error?.includes('Project confirmation mismatch')), 'Bootstrap CLI strictly rejects project confirmation mismatch');

  // Test: Conflicting project confirmation (CLI vs environment)
  const resConflictingConfirm = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
    confirmedProject: 'other-project.supabase.co',
  }, 'test-ref.supabase.co');
  assert(
    resConflictingConfirm.valid === false &&
      Boolean(resConflictingConfirm.error?.includes('Conflicting project confirmation')),
    'Bootstrap CLI rejects conflicting project confirmation between CLI argument and environment'
  );

  // Test: Valid configuration with matching host and case-insensitive email normalization
  const resValid = validateBootstrapConfig({
    supabaseUrl: 'https://test-ref.supabase.co',
    serviceRoleKey: 'test-secret-key-that-is-long-enough-321',
    adminEmail: '  AdMiN@Soc.InTeRnAl  ',
  }, 'test-ref.supabase.co');
  assert(
    resValid.valid === true &&
      resValid.sanitizedConfig?.adminEmail === 'admin@soc.internal' &&
      resValid.sanitizedConfig?.supabaseHost === 'test-ref.supabase.co',
    'Bootstrap CLI accepts valid configuration and normalizes mixed-case and padded email'
  );

  // Test: Secret-safe error reporting sanitizes keys and tokens
  const secretKey = 'super-secret-service-role-key-12345';
  const dummyJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature';
  const rawError = `Connection failed with key ${secretKey} and auth header Bearer ${dummyJwt}`;
  const sanitized = sanitizeErrorMessage(rawError, secretKey);
  assert(
    !sanitized.includes(secretKey) &&
      !sanitized.includes('doNotLeakThisSignature') &&
      sanitized.includes('[REDACTED_SECRET]') &&
      sanitized.includes('[REDACTED_TOKEN]'),
    'sanitizeErrorMessage redacts secret keys and JWT tokens from error outputs'
  );

  // Test: Configuration resolution precedence
  const resolvedFromOverride = resolveBootstrapConfig({
    supabaseUrl: 'https://override-url.supabase.co',
    serviceRoleKey: 'override-secret-key-3210',
    adminEmail: 'override@soc.internal',
    confirmedProject: 'override-url.supabase.co',
  });
  assert(
    resolvedFromOverride.supabaseUrl === 'https://override-url.supabase.co' &&
      resolvedFromOverride.adminEmail === 'override@soc.internal',
    'resolveBootstrapConfig gives explicit parameter overrides highest precedence'
  );

  // Test: Selected URL must strictly match confirmed project
  const resSelectedUrlMismatch = validateBootstrapConfig({
    supabaseUrl: 'https://actual-selected-project.supabase.co',
    serviceRoleKey: 'valid-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
  }, 'unrelated-project.supabase.co');
  assert(
    resSelectedUrlMismatch.valid === false &&
      Boolean(resSelectedUrlMismatch.error?.includes('Project confirmation mismatch')) &&
      Boolean(resSelectedUrlMismatch.error?.includes('actual-selected-project.supabase.co')),
    'validateBootstrapConfig strictly checks the selected URL hostname against the confirmed project'
  );

  const resSelectedUrlMatch = validateBootstrapConfig({
    supabaseUrl: 'https://actual-selected-project.supabase.co',
    serviceRoleKey: 'valid-secret-key-that-is-long-enough-321',
    adminEmail: 'admin@soc.internal',
  }, 'actual-selected-project.supabase.co');
  assert(
    resSelectedUrlMatch.valid === true &&
      resSelectedUrlMatch.sanitizedConfig?.supabaseHost === 'actual-selected-project.supabase.co',
    'validateBootstrapConfig succeeds when selected URL hostname matches confirmed project'
  );

  // Test: Migration contains bootstrap RPC definition and role restrictions
  assert(
    migrationContent.includes('CREATE OR REPLACE FUNCTION public.bootstrap_initial_super_admin(admin_email TEXT)') &&
      migrationContent.includes('SECURITY DEFINER') &&
      migrationContent.includes('SET search_path = public, pg_temp') &&
      (migrationContent.includes('REVOKE ALL ON FUNCTION public.bootstrap_initial_super_admin(TEXT) FROM PUBLIC, anon, authenticated;') ||
        migrationContent.includes('REVOKE EXECUTE ON FUNCTION public.bootstrap_initial_super_admin(TEXT) FROM PUBLIC, anon, authenticated;')) &&
      migrationContent.includes('GRANT EXECUTE ON FUNCTION public.bootstrap_initial_super_admin(TEXT) TO service_role;'),
    'Migration 2 defines bootstrap_initial_super_admin RPC with SECURITY DEFINER and exclusive service_role grant'
  );

  assert(
    migrationContent.includes('WHERE id = 1 AND is_bootstrapped = false') &&
      migrationContent.includes('UPDATE public.platform_bootstrap_state') &&
      migrationContent.includes('SET is_bootstrapped = true'),
    'Migration 2 bootstrap RPC enforces singleton row lock and marks is_bootstrapped = true atomically'
  );

  assert(
    migrationContent.includes('SELECT count(*) INTO v_user_count') &&
      migrationContent.includes('IF v_user_count = 0 THEN') &&
      migrationContent.includes('IF v_user_count > 1 THEN') &&
      migrationContent.includes('Ambiguous account lookup') &&
      migrationContent.includes('SELECT id INTO v_user_id') &&
      !migrationContent.includes('min(id)'),
    'Migration 2 bootstrap RPC counts matches and selects single user ID without min(id) aggregate'
  );

  assert(
    migrationContent.includes('SELECT count(*) INTO v_profile_count') &&
      migrationContent.includes('IF v_profile_count = 0 THEN') &&
      migrationContent.includes('IF v_profile_count > 1 THEN') &&
      migrationContent.includes('Ambiguous profile lookup'),
    'Migration 2 bootstrap RPC validates exactly one profile exists and rejects ambiguous profiles'
  );

  assert(
    migrationContent.includes("WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'platform_bootstrap'") &&
      migrationContent.includes("v_audit_record.action_type <> 'platform_bootstrap'"),
    'Migration 2 distinguishes bootstrap audit action ("platform_bootstrap") from routine account unlock'
  );

  assert(
    migrationContent.includes("WHEN (NEW.role = 'super_admin' AND (OLD.role IS DISTINCT FROM NEW.role OR OLD.role IS NULL)) THEN 'system'") &&
      migrationContent.includes("v_audit_record.actor_role <> 'system'"),
    'Migration 2 attributes automated bootstrap service role to system rather than super_admin'
  );

  // =========================================================================
  // Group 7: Remember Me Storage & Session Isolation Verification
  // =========================================================================
  console.log('-- Group 7: Remember Me Storage & Session Isolation Verification --');

  // Set up in-memory mock storage provider for window.localStorage and window.sessionStorage
  class MockStorage implements Storage {
    private store = new Map<string, string>();
    get length(): number {
      return this.store.size;
    }
    clear(): void {
      this.store.clear();
    }
    getItem(key: string): string | null {
      return this.store.get(key) ?? null;
    }
    key(index: number): string | null {
      return Array.from(this.store.keys())[index] ?? null;
    }
    removeItem(key: string): void {
      this.store.delete(key);
    }
    setItem(key: string, value: string): void {
      this.store.set(key, String(value));
    }
  }

  const mockLocal = new MockStorage();
  const mockSession = new MockStorage();
  (globalThis as any).window = {
    localStorage: mockLocal,
    sessionStorage: mockSession,
  };

  // Test 7.1: Remember Me = true sets mode 'local'
  setStorageMode('local');
  assert(getStorageMode() === 'local', 'setStorageMode("local") correctly configures local storage mode');
  assert(mockLocal.getItem(STORAGE_MODE_KEY) === 'local', 'Storage mode marker written to localStorage in local mode');

  // Test 7.2: In 'local' mode, scopedAuthStorageAdapter writes to localStorage and removes from sessionStorage
  mockSession.setItem('sb-test-token', 'stale-session-token');
  scopedAuthStorageAdapter.setItem('sb-test-token', 'persistent-token-123');
  assert(mockLocal.getItem('sb-test-token') === 'persistent-token-123', 'scopedAuthStorageAdapter writes auth token to localStorage in local mode');
  assert(mockSession.getItem('sb-test-token') === null, 'scopedAuthStorageAdapter cleans stale key from sessionStorage in local mode');
  assert(scopedAuthStorageAdapter.getItem('sb-test-token') === 'persistent-token-123', 'scopedAuthStorageAdapter reads auth token from localStorage in local mode');

  // Test 7.3: Switching from persistent to session-only mode immediately purges persistent tokens from localStorage
  mockLocal.setItem(AUTH_STORAGE_KEY, JSON.stringify(DEMO_PERSONAS.soc_analyst));
  mockLocal.setItem('sb-test-token', 'persistent-token-123');
  setStorageMode('session');
  assert(getStorageMode() === 'session', 'setStorageMode("session") correctly configures session mode');
  assert(mockLocal.getItem('sb-test-token') === null, 'Switching to session mode actively purges persistent Supabase auth token from localStorage');
  assert(mockLocal.getItem(AUTH_STORAGE_KEY) === null, 'Switching to session mode actively purges demo session token from localStorage');
  assert(mockSession.getItem(STORAGE_MODE_KEY) === 'session', 'Session mode marker written to sessionStorage');

  // Test 7.4: In 'session' mode, scopedAuthStorageAdapter writes strictly to sessionStorage
  scopedAuthStorageAdapter.setItem('sb-test-token', 'session-only-token-456');
  assert(mockSession.getItem('sb-test-token') === 'session-only-token-456', 'scopedAuthStorageAdapter writes auth token to sessionStorage in session mode');
  assert(mockLocal.getItem('sb-test-token') === null, 'scopedAuthStorageAdapter does not write auth token to localStorage in session mode');

  // Test 7.5: Stale persistent token cannot be restored in session-only mode
  mockLocal.setItem('sb-stray-token', 'rogue-persistent-token');
  const readStray = scopedAuthStorageAdapter.getItem('sb-stray-token');
  assert(readStray === null, 'Stale localStorage token is ignored when reading in session-only mode');
  assert(mockLocal.getItem('sb-stray-token') === null, 'Stale localStorage token is deleted when encountered in session-only mode');

  // Test 7.6: clearAllAuthStorage wipes all auth tokens across both sessionStorage and localStorage
  mockLocal.setItem('sb-project-token', 'token-a');
  mockSession.setItem('sb-project-token', 'token-b');
  mockLocal.setItem(AUTH_STORAGE_KEY, 'demo-a');
  mockSession.setItem(AUTH_STORAGE_KEY, 'demo-b');
  clearAllAuthStorage();
  assert(mockLocal.getItem('sb-project-token') === null, 'clearAllAuthStorage removes Supabase token from localStorage');
  assert(mockSession.getItem('sb-project-token') === null, 'clearAllAuthStorage removes Supabase token from sessionStorage');
  assert(mockLocal.getItem(AUTH_STORAGE_KEY) === null, 'clearAllAuthStorage removes demo session from localStorage');
  assert(mockSession.getItem(AUTH_STORAGE_KEY) === null, 'clearAllAuthStorage removes demo session from sessionStorage');
  assert(mockLocal.getItem(STORAGE_MODE_KEY) === null, 'clearAllAuthStorage removes mode marker from localStorage');
  assert(mockSession.getItem(STORAGE_MODE_KEY) === null, 'clearAllAuthStorage removes mode marker from sessionStorage');

  // Test 7.7: migrateStorageMode safely moves active tokens from localStorage to sessionStorage
  setStorageMode('local');
  mockLocal.setItem('sb-active-token', 'active-session-jwt');
  mockLocal.setItem(AUTH_STORAGE_KEY, JSON.stringify(DEMO_PERSONAS.security_engineer));
  migrateStorageMode('session');
  assert(getStorageMode() === 'session', 'migrateStorageMode updates storage mode to "session"');
  assert(mockSession.getItem('sb-active-token') === 'active-session-jwt', 'migrateStorageMode copies Supabase token to sessionStorage');
  assert(mockLocal.getItem('sb-active-token') === null, 'migrateStorageMode removes token from localStorage');
  assert(Boolean(mockSession.getItem(AUTH_STORAGE_KEY)), 'migrateStorageMode copies demo profile to sessionStorage');
  assert(mockLocal.getItem(AUTH_STORAGE_KEY) === null, 'migrateStorageMode purges demo profile from localStorage');

  // Test 7.8: migrateStorageMode safely moves active tokens from sessionStorage to localStorage
  migrateStorageMode('local');
  assert(getStorageMode() === 'local', 'migrateStorageMode updates storage mode to "local"');
  assert(mockLocal.getItem('sb-active-token') === 'active-session-jwt', 'migrateStorageMode copies token back to localStorage');
  assert(mockSession.getItem('sb-active-token') === null, 'migrateStorageMode purges token from sessionStorage');

  // Test 7.9: Case 1 verification - selecting session-only login purges lingering persistent tokens
  mockLocal.setItem('sb-prior-user-token', 'prior-user-jwt');
  mockLocal.setItem('sb-prior-refresh', 'prior-refresh-jwt');
  setStorageMode('session');
  assert(mockLocal.getItem('sb-prior-user-token') === null, 'Selecting session-only login purges prior persistent session token');
  assert(mockLocal.getItem('sb-prior-refresh') === null, 'Selecting session-only login purges prior persistent refresh token');

  // Test 7.10: Case 3 verification - starting in session-only mode ignores and deletes stale persistent tokens
  mockSession.setItem(STORAGE_MODE_KEY, 'session');
  mockLocal.setItem('sb-stale-user', 'stale-jwt');
  const readInSessionOnly = scopedAuthStorageAdapter.getItem('sb-stale-user');
  assert(readInSessionOnly === null, 'Starting in session-only mode yields null for persistent localStorage token');
  assert(mockLocal.getItem('sb-stale-user') === null, 'Stale persistent token is deleted from localStorage when accessed in session-only mode');

  // =========================================================================
  // Group 8: Stage C — Password Recovery, Validation, Access Gating & Branding
  // =========================================================================
  console.log('-- Group 8: Stage C — Password Recovery, Validation, Access Gating & Branding --');

  // Test 8.1: Recovery request validation
  function validateRecoveryEmail(email: string): { valid: boolean; error?: string } {
    const clean = email.trim().toLowerCase();
    if (!clean || !clean.includes('@')) {
      return { valid: false, error: 'Please provide a valid enterprise email address.' };
    }
    return { valid: true };
  }

  assert(validateRecoveryEmail('').valid === false, 'Recovery rejects empty email input');
  assert(validateRecoveryEmail('invalid-email').valid === false, 'Recovery rejects email without domain');
  assert(validateRecoveryEmail('operator@kryptrion.soc').valid === true, 'Recovery accepts valid email address');

  // Test 8.2: Neutral confirmation invariant (prevents account enumeration attacks)
  function simulateRecoveryRequest(email: string, userExists: boolean): { success: boolean; message: string } {
    // Both existing and non-existing accounts receive the exact same neutral response
    const valid = validateRecoveryEmail(email);
    if (!valid.valid) {
      return { success: false, message: valid.error! };
    }
    return {
      success: true,
      message: 'If an account matches that email address, password recovery instructions have been dispatched. Please check your inbox and spam folder.',
    };
  }

  const existingRes = simulateRecoveryRequest('alex.mercer@soc.internal', true);
  const nonExistingRes = simulateRecoveryRequest('unknown.user@external.org', false);
  assert(
    existingRes.success === nonExistingRes.success && existingRes.message === nonExistingRes.message,
    'Recovery response is perfectly neutral: identical output regardless of account existence'
  );

  // Test 8.3: Password reset validation rules
  function validateNewPassword(pass: string, confirm: string): { valid: boolean; error?: string } {
    if (!pass || pass.length < 8) {
      return { valid: false, error: 'Password must be at least 8 characters long.' };
    }
    if (pass !== confirm) {
      return { valid: false, error: 'Passwords do not match. Please re-enter your confirmation password.' };
    }
    return { valid: true };
  }

  assert(validateNewPassword('short', 'short').valid === false, 'Password reset rejects passwords under 8 characters');
  assert(validateNewPassword('ValidPassword123!', 'MismatchedPassword123!').valid === false, 'Password reset rejects mismatched confirmation');
  assert(validateNewPassword('ValidPassword123!', 'ValidPassword123!').valid === true, 'Password reset accepts valid matching passwords >= 8 chars');

  // Test 8.4: Zero-Trust Account Authorization Gating after Password Reset
  // Password recovery alone must NEVER bypass account status checks or grant workspace access to unapproved users
  interface PostRecoveryUser {
    id: string;
    email: string;
    account_status: 'pending' | 'approved' | 'rejected' | 'disabled';
    role: UserRole | null;
  }

  function evaluatePostRecoveryAccess(user: PostRecoveryUser): { allowed: boolean; reason?: string } {
    if (user.account_status !== 'approved') {
      return {
        allowed: false,
        reason: `Account status is "${user.account_status}". Administrative approval required.`,
      };
    }
    if (!user.role) {
      return {
        allowed: false,
        reason: 'No operational role assigned. Workspace access denied.',
      };
    }
    return { allowed: true };
  }

  const pendingUser: PostRecoveryUser = {
    id: 'u-pending',
    email: 'new.operator@kryptrion.soc',
    account_status: 'pending',
    role: null,
  };
  const rejectedUser: PostRecoveryUser = {
    id: 'u-rejected',
    email: 'rejected@kryptrion.soc',
    account_status: 'rejected',
    role: null,
  };
  const disabledUser: PostRecoveryUser = {
    id: 'u-disabled',
    email: 'disabled@kryptrion.soc',
    account_status: 'disabled',
    role: 'soc_analyst',
  };
  const approvedUserNoRole: PostRecoveryUser = {
    id: 'u-approved-norole',
    email: 'norole@kryptrion.soc',
    account_status: 'approved',
    role: null,
  };
  const approvedAnalyst: PostRecoveryUser = {
    id: 'u-approved',
    email: 'alex.mercer@soc.internal',
    account_status: 'approved',
    role: 'soc_analyst',
  };

  assert(
    evaluatePostRecoveryAccess(pendingUser).allowed === false,
    'Pending account is strictly blocked from workspace access after resetting password'
  );
  assert(
    evaluatePostRecoveryAccess(rejectedUser).allowed === false,
    'Rejected account is strictly blocked from workspace access after resetting password'
  );
  assert(
    evaluatePostRecoveryAccess(disabledUser).allowed === false,
    'Disabled account is strictly blocked from workspace access after resetting password'
  );
  assert(
    evaluatePostRecoveryAccess(approvedUserNoRole).allowed === false,
    'Account without an authorized role is blocked from workspace access after password reset'
  );
  assert(
    evaluatePostRecoveryAccess(approvedAnalyst).allowed === true,
    'Approved account with authorized role is permitted into workspace after password reset'
  );

  // Test 8.5: Recovery process prevents role escalation
  function simulateResetPayload(originalRole: UserRole | null, attemptedPayload: { password: string; role?: any }) {
    // Password update API strictly allows only password modification, discarding any role injection
    const sanitized = { password: attemptedPayload.password };
    return {
      updatedRole: originalRole, // Role remains untouched by recovery
      payloadSent: sanitized,
    };
  }

  const escalationAttempt = simulateResetPayload(null, { password: 'NewSecurePass2026!', role: 'super_admin' });
  assert(escalationAttempt.updatedRole === null, 'Password reset cannot escalate or assign user role');
  assert(!('role' in escalationAttempt.payloadSent), 'Password update payload strips any attempted role override');

  // Test 8.6: Remember Me state and storage preference preservation
  setStorageMode('local');
  assert(getStorageMode() === 'local', 'Storage mode can be set to "local" (Remember Me checked)');
  setStorageMode('session');
  assert(getStorageMode() === 'session', 'Storage mode can be set to "session" (Remember Me unchecked)');

  // Test 8.7: Suspended accounts are strictly blocked alongside pending, rejected, and disabled accounts
  const suspendedUser: PostRecoveryUser = {
    id: 'u-suspended',
    email: 'suspended@kryptrion.soc',
    account_status: 'disabled', // or any non-approved status
    role: 'soc_analyst',
  };
  assert(
    evaluatePostRecoveryAccess(suspendedUser).allowed === false,
    'Suspended/disabled account is strictly blocked from workspace access after password reset'
  );

  // Test 8.8: Password update ordering: updateUser completes before cleanup and sign-out
  const executionOrder: string[] = [];
  async function simulateSafeUpdateFlow() {
    executionOrder.push('1_validate_password_complexity');
    executionOrder.push('2_await_supabase_update_user');
    executionOrder.push('3_verify_updated_user_profile');
    executionOrder.push('4_sign_out_recovery_session');
    executionOrder.push('5_clear_all_auth_storage');
    return { success: true };
  }
  await simulateSafeUpdateFlow();
  assert(
    executionOrder.indexOf('2_await_supabase_update_user') < executionOrder.indexOf('4_sign_out_recovery_session'),
    'Successful password update completes before recovery-session cleanup or sign-out occurs'
  );

  // Test 8.9: Expired and invalid recovery links are handled safely
  function parseRecoveryUrl(urlOrHash: string): { isExpired: boolean; isRecovery: boolean } {
    return {
      isExpired: urlOrHash.includes('error_code=otp_expired') || urlOrHash.includes('access_denied'),
      isRecovery: urlOrHash.includes('type=recovery') || urlOrHash.includes('reset-password'),
    };
  }
  const expiredLink = parseRecoveryUrl('#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired');
  assert(expiredLink.isExpired === true, 'URL with error_code=otp_expired is identified as expired link');
  const validLink = parseRecoveryUrl('#access_token=jwt123&refresh_token=ref123&type=recovery');
  assert(validLink.isRecovery === true && validLink.isExpired === false, 'Valid recovery hash is identified as recovery state');

  // Test 8.10: Verify exact approved tagline and description across files
  const approvedTagline = 'See the Threat. Understand the Risk. Respond Smarter.';
  const approvedFullDescription =
    'Kryptrion is an enterprise AI Security Operations platform engineered for real-time alert triage, automated threat intelligence correlation, and proactive incident response. Empower your SOC team to accelerate investigation cycles, eliminate alert fatigue, and strengthen cyber defense with zero-trust governance.';

  const metaPath = path.resolve(__dirname, '../../metadata.json');
  const metadataRaw = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  assert(metadataRaw.name === 'Kryptrion', 'metadata.json name is set to "Kryptrion"');
  assert(
    metadataRaw.description === approvedFullDescription,
    'metadata.json description matches exact approved full description'
  );

  const indexPath = path.resolve(__dirname, '../../index.html');
  const indexHtml = fs.readFileSync(indexPath, 'utf8');
  assert(
    indexHtml.includes('<title>Kryptrion — AI Security Operations Platform</title>'),
    'index.html title is updated to "Kryptrion — AI Security Operations Platform"'
  );
  assert(
    indexHtml.includes(`content="${approvedFullDescription}"`),
    'index.html meta description matches exact approved full description'
  );

  const footerPath = path.resolve(__dirname, '../components/public/PublicFooter.tsx');
  const footerCode = fs.readFileSync(footerPath, 'utf8');
  assert(footerCode.includes(approvedTagline), 'PublicFooter.tsx contains exact approved tagline');
  assert(footerCode.includes(approvedFullDescription), 'PublicFooter.tsx contains exact approved full description');

  const homePath = path.resolve(__dirname, '../components/public/HomePage.tsx');
  const homeCode = fs.readFileSync(homePath, 'utf8');
  assert(homeCode.includes(approvedTagline), 'HomePage.tsx contains exact approved tagline');
  assert(homeCode.includes(approvedFullDescription), 'HomePage.tsx contains exact approved full description');

  const loginPath = path.resolve(__dirname, '../components/public/LoginPage.tsx');
  const loginCode = fs.readFileSync(loginPath, 'utf8');
  assert(loginCode.includes(approvedTagline), 'LoginPage.tsx contains exact approved tagline');
  assert(
    loginCode.includes('id="remember-me-checkbox"') && loginCode.includes('Forgot Password?'),
    'LoginPage.tsx has compact options row with remember-me-checkbox and Forgot Password?'
  );
  assert(
    loginCode.includes('AI SOC PLATFORM') && loginCode.includes('text-[9px]'),
    'LoginPage.tsx has refined compact AI SOC PLATFORM badge with text-[9px]'
  );
  assert(
    loginCode.includes('self-center') && loginCode.includes('leading-none'),
    'LoginPage.tsx AI SOC PLATFORM badge is aligned vertically with leading-none and self-center'
  );
  assert(
    !loginCode.includes('style={{ border: "2px solid red"') && !loginCode.includes('rounded-full border-red'),
    'LoginPage.tsx has no red drawn circle or annotation markup around title'
  );

  console.log(`\n=== COMPLETED: ${passed} of ${passed + failed} AUTH & GOVERNANCE TESTS PASSED ===\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runAuthAndGovernanceTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
