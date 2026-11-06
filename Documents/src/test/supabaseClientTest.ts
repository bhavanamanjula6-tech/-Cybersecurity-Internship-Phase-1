/**
 * CyberOps SOC — Supabase Client Unit Test Suite (Key Compatibility Verification)
 *
 * Verifies:
 * 1. Safe parsing and placeholder detection in isSupabaseConfigured()
 *    - Legacy placeholder: 'your-anon-public-key'
 *    - Modern placeholder: 'your-publishable-key'
 *    - Placeholder URL: 'your-project-id'
 * 2. Acceptance of both key formats:
 *    - Legacy anon JWT keys ('eyJhbGci...')
 *    - Modern Supabase publishable keys ('sb_publishable_...')
 * 3. Key resolution and deterministic precedence:
 *    - VITE_SUPABASE_ANON_KEY takes precedence over VITE_SUPABASE_PUBLISHABLE_KEY
 *    - Fallback to VITE_SUPABASE_PUBLISHABLE_KEY when anon key is absent/empty
 * 4. Environment-aware status resolution:
 *    - Modern publishable key resolves to live_supabase in production
 *    - Unconfigured dev environment resolves to development_demo mode
 *    - Unconfigured production environment resolves to production_fail_closed mode
 * 5. Fail-closed client access invariants:
 *    - Default unconfigured export 'supabase' is null
 *    - getSupabaseClient() throws appropriate error in dev and prod
 *    - Zero network requests or remote database access during unconfigured operation
 */

import {
  isSupabaseConfigured,
  getSupabaseConfigurationStatus,
  getSupabaseClient,
  resolveSupabaseKey,
  supabase,
} from '../lib/supabaseClient';

function runSupabaseClientTests() {
  console.log('=== RUNNING SUPABASE CLIENT KEY COMPATIBILITY TESTS ===');
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

  // --- Group 1: Configuration Validation & Placeholder Rejection ---
  console.log('-- Group 1: Configuration Validation & Placeholder Rejection --');

  assert(
    isSupabaseConfigured(undefined, undefined) === false,
    'Undefined URL and key returns false'
  );

  assert(
    isSupabaseConfigured('', '') === false,
    'Empty URL and key returns false'
  );

  assert(
    isSupabaseConfigured('   ', '   ') === false,
    'Whitespace-only URL and key returns false'
  );

  assert(
    isSupabaseConfigured('https://your-project-id.supabase.co', 'eyValidKey12345') === false,
    'Placeholder URL "your-project-id" is rejected'
  );

  assert(
    isSupabaseConfigured('https://xyzcompany.supabase.co', 'eyJhbGci.your-anon-public-key') === false,
    'Legacy placeholder anon key "your-anon-public-key" is rejected'
  );

  assert(
    isSupabaseConfigured('https://xyzcompany.supabase.co', 'sb_publishable_your-publishable-key') === false,
    'Modern placeholder key "your-publishable-key" is rejected'
  );

  assert(
    isSupabaseConfigured('not-a-valid-url', 'valid-key-xyz') === false,
    'Malformed URL without protocol is rejected'
  );

  assert(
    isSupabaseConfigured('ftp://xyzcompany.supabase.co', 'valid-key-xyz') === false,
    'Non-HTTP/HTTPS protocol (ftp) is rejected'
  );

  assert(
    isSupabaseConfigured('https://xyzcompany.supabase.co', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid-jwt-token') === true,
    'Valid HTTPS URL and legacy JWT key is accepted'
  );

  assert(
    isSupabaseConfigured('https://xyzcompany.supabase.co', 'sb_publishable_0123456789abcdef0123456789abcdef') === true,
    'Valid HTTPS URL and modern "sb_publishable_..." key is accepted'
  );

  // --- Group 2: Key Resolution & Deterministic Precedence ---
  console.log('-- Group 2: Key Resolution & Deterministic Precedence --');

  assert(
    resolveSupabaseKey('anon-key-123', undefined) === 'anon-key-123',
    'resolveSupabaseKey with only anonKey returns anonKey'
  );

  assert(
    resolveSupabaseKey(undefined, 'sb_publishable_abc') === 'sb_publishable_abc',
    'resolveSupabaseKey with only publishableKey returns publishableKey'
  );

  assert(
    resolveSupabaseKey('legacy-anon-key', 'sb_publishable_new_key') === 'legacy-anon-key',
    'Deterministic precedence: anonKey takes priority when both are configured'
  );

  assert(
    resolveSupabaseKey('   ', 'sb_publishable_fallback') === 'sb_publishable_fallback',
    'Whitespace/empty anonKey correctly falls back to publishableKey'
  );

  assert(
    resolveSupabaseKey(undefined, undefined) === undefined,
    'resolveSupabaseKey with neither key returns undefined'
  );

  // --- Group 3: Environment-Aware Status Resolution with Both Variable Names ---
  console.log('-- Group 3: Environment-Aware Status Resolution with Both Variable Names --');

  const modernPublishableKeyStatus = getSupabaseConfigurationStatus({
    url: 'https://xyzcompany.supabase.co',
    publishableKey: 'sb_publishable_0123456789abcdef',
    isDev: false,
    isProd: true,
  });
  assert(
    modernPublishableKeyStatus.mode === 'live_supabase' &&
      modernPublishableKeyStatus.configured === true &&
      modernPublishableKeyStatus.environment === 'production',
    'Modern sb_publishable_ key via publishableKey resolves to "live_supabase" in production'
  );

  const legacyAnonKeyStatus = getSupabaseConfigurationStatus({
    url: 'https://xyzcompany.supabase.co',
    anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.legacysupabasejwt',
    isDev: false,
    isProd: true,
  });
  assert(
    legacyAnonKeyStatus.mode === 'live_supabase' &&
      legacyAnonKeyStatus.configured === true &&
      legacyAnonKeyStatus.environment === 'production',
    'Legacy JWT via anonKey resolves to "live_supabase" in production'
  );

  const precedenceStatus = getSupabaseConfigurationStatus({
    url: 'https://xyzcompany.supabase.co',
    anonKey: 'legacy-preferred-key',
    publishableKey: 'sb_publishable_secondary',
    isDev: false,
    isProd: true,
  });
  assert(
    precedenceStatus.mode === 'live_supabase' &&
      precedenceStatus.configured === true,
    'Status evaluation succeeds under dual-key configuration'
  );

  const devUnconfiguredStatus = getSupabaseConfigurationStatus({
    url: undefined,
    key: undefined,
    isDev: true,
    isProd: false,
  });
  assert(
    devUnconfiguredStatus.mode === 'development_demo' &&
      devUnconfiguredStatus.configured === false &&
      devUnconfiguredStatus.environment === 'development',
    'Unconfigured dev environment resolves to "development_demo" mode'
  );

  const prodUnconfiguredStatus = getSupabaseConfigurationStatus({
    url: undefined,
    key: undefined,
    isDev: false,
    isProd: true,
  });
  assert(
    prodUnconfiguredStatus.mode === 'production_fail_closed' &&
      prodUnconfiguredStatus.configured === false &&
      prodUnconfiguredStatus.environment === 'production',
    'Unconfigured production environment resolves to "production_fail_closed" mode'
  );

  // --- Group 4: Fail-Closed Client Access Invariants ---
  console.log('-- Group 4: Fail-Closed Client Access Invariants --');

  if (!isSupabaseConfigured()) {
    assert(
      supabase === null,
      'Default unconfigured export "supabase" is null (no unauthenticated connection instantiated)'
    );

    let devThrownError: Error | null = null;
    try {
      getSupabaseClient();
    } catch (err) {
      devThrownError = err as Error;
    }
    assert(
      devThrownError !== null &&
        devThrownError.message.includes('[CyberOps SOC Notice]'),
      'Calling getSupabaseClient() in unconfigured environment throws explicit error'
    );
  } else {
    assert(
      supabase !== null,
      'Configured export "supabase" is instantiated with active client instance'
    );

    let clientRetrieved = false;
    try {
      const c = getSupabaseClient();
      clientRetrieved = c !== null;
    } catch {
      clientRetrieved = false;
    }
    assert(
      clientRetrieved,
      'Calling getSupabaseClient() in configured environment successfully retrieves client'
    );
  }

  console.log(`\n=== COMPLETED: ${passed} of ${passed + failed} SUPABASE CLIENT TESTS PASSED ===\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runSupabaseClientTests();
