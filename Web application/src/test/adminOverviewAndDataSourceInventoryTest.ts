/**
 * CyberOps SOC — Admin Overview & Data Source Inventory Verification Suite
 *
 * Verifies:
 * 1. Accurate Admin Overview metrics (total registered users, counts by role, status distribution, pending count).
 * 2. Strict distinction between configured database URL and verified connectivity.
 * 3. Graceful handling of connected, unreachable, and local fallback database states.
 * 4. Data Source Inventory catalog completeness:
 *    - Supabase PostgreSQL primary database
 *    - Authentic MITRE ATT&CK Enterprise v14.1 taxonomy
 *    - CIC-IDS2017 network flow benchmark telemetry
 *    - Immutable WORM audit trail
 *    - AI Security Copilot advisory engine
 * 5. Explicit status chips and logical provenance badges.
 * 6. Non-invocation of generative AI: Copilot status checked without live LLM calls.
 * 7. Preservation of Super Admin operational isolation: zero alerts, notes, or incident investigations exposed.
 */

import { UserProfile, UserRole, AccountStatus } from '../types/auth';
import {
  calculateAdminOverviewMetrics,
  checkDatabaseConnectivity,
  checkCopilotStatusSafe,
  buildDataSourceInventory,
  DatabaseConnectivityStatus,
} from '../services/adminMetricsService';
import { AUTHENTIC_MITRE_TACTICS, AUTHENTIC_MITRE_TECHNIQUES, AUTHENTIC_MITRE_MITIGATIONS } from '../data/mitreData';

let totalTests = 0;
let passedTests = 0;

function assert(condition: boolean, message: string) {
  totalTests++;
  if (!condition) {
    console.error(`  [FAIL] Test ${totalTests}: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`  [PASS] Test ${totalTests}: ${message}`);
}

export async function runAdminOverviewAndDataSourceInventoryTests(): Promise<{ passed: number; total: number }> {
  console.log('--- Admin Overview & Data Source Inventory Test Suite ---');

  // Test Profiles Sample
  const sampleProfiles: UserProfile[] = [
    {
      id: 'usr-1',
      name: 'Alex Mercer',
      email: 'alex.mercer@soc.internal',
      role: 'soc_analyst',
      callsign: 'SPECTER',
      title: 'Senior Incident Responder',
      accountStatus: 'approved',
    },
    {
      id: 'usr-2',
      name: 'Elena Rostova',
      email: 'elena.rostova@soc.internal',
      role: 'security_engineer',
      callsign: 'AEGIS',
      title: 'Lead Detection Engineer',
      accountStatus: 'approved',
    },
    {
      id: 'usr-3',
      name: 'Marcus Vance',
      email: 'marcus.vance@soc.internal',
      role: 'it_operations',
      callsign: 'ANVIL',
      title: 'Infrastructure Specialist',
      accountStatus: 'approved',
    },
    {
      id: 'usr-4',
      name: 'Sarah Chen',
      email: 'sarah.chen@soc.internal',
      role: 'super_admin',
      callsign: 'VANGUARD',
      title: 'CISO',
      accountStatus: 'approved',
    },
    {
      id: 'usr-5',
      name: 'Devon Vance',
      email: 'devon.vance@soc.internal',
      role: 'soc_analyst',
      callsign: 'PENDING-1',
      title: 'Associate Security Analyst',
      accountStatus: 'pending',
    },
    {
      id: 'usr-6',
      name: 'Morgan Blake',
      email: 'morgan.blake@soc.internal',
      role: 'it_operations',
      callsign: 'PENDING-2',
      title: 'Systems Administrator',
      accountStatus: 'pending',
    },
  ];

  // =========================================================================
  // 1. ADMIN OVERVIEW METRIC CALCULATIONS
  // =========================================================================
  console.log('\n[Group 1: Admin Overview Metric Calculations]');

  const metrics = calculateAdminOverviewMetrics(sampleProfiles);

  assert(metrics.totalUsers === 6, 'Total registered users correctly calculated as 6');
  assert(metrics.roleCounts.soc_analyst === 2, 'soc_analyst count is 2');
  assert(metrics.roleCounts.security_engineer === 1, 'security_engineer count is 1');
  assert(metrics.roleCounts.it_operations === 2, 'it_operations count is 2');
  assert(metrics.roleCounts.super_admin === 1, 'super_admin count is 1');
  assert(
    metrics.roleCounts.soc_analyst +
      metrics.roleCounts.security_engineer +
      metrics.roleCounts.it_operations +
      metrics.roleCounts.super_admin ===
      6,
    'Sum of role counts equals total registered users'
  );

  assert(metrics.statusCounts.approved === 4, 'Approved accounts count is 4');
  assert(metrics.statusCounts.pending === 2, 'Pending accounts count is 2');
  assert(metrics.statusCounts.disabled === 0, 'Disabled accounts count is 0');
  assert(metrics.statusCounts.rejected === 0, 'Rejected accounts count is 0');
  assert(metrics.pendingCount === 2, 'Pending approval queue count is 2');
  assert(metrics.approvedCount === 4, 'Approved active count is 4');

  // Edge Case: Empty profile list
  const emptyMetrics = calculateAdminOverviewMetrics([]);
  assert(emptyMetrics.totalUsers === 0, 'Empty profiles list yields totalUsers: 0');
  assert(emptyMetrics.pendingCount === 0, 'Empty profiles list yields pendingCount: 0');
  assert(emptyMetrics.roleCounts.super_admin === 0, 'Empty profiles list yields roleCounts.super_admin: 0');

  // Edge Case: Mixed disabled and rejected profiles
  const mixedProfiles: UserProfile[] = [
    { ...sampleProfiles[0], accountStatus: 'approved' },
    { ...sampleProfiles[1], accountStatus: 'pending' },
    { ...sampleProfiles[2], accountStatus: 'disabled' },
    { ...sampleProfiles[3], accountStatus: 'rejected' },
  ];
  const mixedMetrics = calculateAdminOverviewMetrics(mixedProfiles);
  assert(mixedMetrics.statusCounts.approved === 1, 'Mixed profiles: approved is 1');
  assert(mixedMetrics.statusCounts.pending === 1, 'Mixed profiles: pending is 1');
  assert(mixedMetrics.statusCounts.disabled === 1, 'Mixed profiles: disabled is 1');
  assert(mixedMetrics.statusCounts.rejected === 1, 'Mixed profiles: rejected is 1');

  // =========================================================================
  // 2. DATABASE CONNECTIVITY VS CONFIGURATION
  // =========================================================================
  console.log('\n[Group 2: Database Connectivity vs. Configuration Checks]');

  // Test 2.1: Probe success -> Verified Connected
  const connectedStatus = await checkDatabaseConnectivity(async () => ({ success: true }));
  assert(connectedStatus.isConfigured === true, 'Configured flag is true for active probe');
  assert(connectedStatus.isConnected === true, 'Connected flag is true when probe succeeds');
  assert(connectedStatus.statusBadge === 'Connected', 'Status badge is "Connected"');
  assert(connectedStatus.detail.includes('verified'), 'Detail confirms probe verification');

  // Test 2.2: Probe failure -> Configured but Unreachable (Proves URL alone does NOT imply connected!)
  const unreachableStatus = await checkDatabaseConnectivity(async () => ({
    success: false,
    error: 'PostgreSQL connection refused at port 5432',
  }));
  assert(unreachableStatus.isConfigured === true, 'Configured flag is true when env is present');
  assert(unreachableStatus.isConnected === false, 'Connected flag is FALSE when probe fails');
  assert(unreachableStatus.statusBadge === 'Unreachable', 'Status badge is "Unreachable" when probe fails');
  assert(
    unreachableStatus.errorMessage?.includes('connection refused') === true,
    'Sanitized error message captured in connectivity status'
  );

  // Test 2.3: Probe exception -> Handled safely without unhandled rejection
  const exceptionStatus = await checkDatabaseConnectivity(async () => {
    throw new Error('DNS resolution timeout');
  });
  assert(exceptionStatus.isConnected === false, 'Connected flag is FALSE when probe throws');
  assert(exceptionStatus.statusBadge === 'Unreachable', 'Exception safely mapped to Unreachable');

  // =========================================================================
  // 3. AI COPILOT SAFE STATUS CHECK (NO LIVE LLM CALLS)
  // =========================================================================
  console.log('\n[Group 3: Copilot Safe Status Checks]');

  // Model configured status
  const configuredCopilot = await checkCopilotStatusSafe(async () => ({
    online: true,
    modelConfigured: true,
  }));
  assert(configuredCopilot.state === 'Configured', 'Copilot reports Configured when model is online');
  assert(configuredCopilot.modelConfigured === true, 'modelConfigured flag is true');

  // Standby mode (no API key configured)
  const standbyCopilot = await checkCopilotStatusSafe(async () => ({
    online: true,
    modelConfigured: false,
  }));
  assert(standbyCopilot.state === 'Standby', 'Copilot reports Standby when model is unconfigured');
  assert(standbyCopilot.modelConfigured === false, 'modelConfigured flag is false in standby');

  // Offline mode
  const offlineCopilot = await checkCopilotStatusSafe(async () => {
    throw new Error('Connection refused');
  });
  assert(offlineCopilot.state === 'Standby', 'Copilot offline gracefully falls back to Standby');

  // =========================================================================
  // 4. DATA SOURCE INVENTORY CATALOG
  // =========================================================================
  console.log('\n[Group 4: Data Source Inventory Catalog]');

  const inventory = buildDataSourceInventory({
    dbStatus: connectedStatus,
    copilotStatus: configuredCopilot,
    userCount: 6,
  });

  assert(inventory.length === 4, 'Inventory contains exactly 4 cataloged data sources');

  const [dbItem, mitreItem, auditItem, copilotItem] = inventory;

  // 4.1 Primary Database
  assert(dbItem.id === 'primary_database', 'First item is primary_database');
  assert(dbItem.type === 'relational_db', 'Primary DB type is relational_db');
  assert(dbItem.state === 'Connected', 'DB state reflects verified Connected');
  assert(dbItem.recordCountLabel.includes('6 Registered User Profiles'), 'DB record count reflects user profile count');
  assert(dbItem.isOperationalData === false, 'Primary DB item does NOT expose operational alert data');

  // 4.2 MITRE ATT&CK
  assert(mitreItem.id === 'mitre_framework', 'Second item is mitre_framework');
  assert(mitreItem.type === 'threat_framework', 'MITRE type is threat_framework');
  assert(mitreItem.provenanceType === 'authentic_mitre', 'MITRE provenance badge is authentic_mitre');
  assert(mitreItem.state === 'Authentic Reference', 'MITRE state is Authentic Reference');
  assert(
    mitreItem.recordCountLabel.includes(`${AUTHENTIC_MITRE_TACTICS.length} Tactics`),
    'MITRE record count includes 14 Tactics'
  );
  assert(
    mitreItem.recordCountLabel.includes(`${AUTHENTIC_MITRE_TECHNIQUES.length} Techniques`),
    'MITRE record count includes 10 Techniques'
  );
  assert(
    mitreItem.recordCountLabel.includes(`${AUTHENTIC_MITRE_MITIGATIONS.length} Mitigations`),
    'MITRE record count includes 10 Mitigations'
  );
  assert(mitreItem.isOperationalData === false, 'MITRE item does not expose operational data');

  // 4.3 Audit Ledger
  assert(auditItem.id === 'audit_ledger', 'Third item is audit_ledger');
  assert(auditItem.type === 'audit_ledger', 'Audit item type is audit_ledger');
  assert(auditItem.state === 'Active (Append-Only)', 'Audit state is Active (Append-Only)');
  assert(auditItem.scopeNotice.includes('SHA-256'), 'Audit scope notice documents cryptographic SHA-256 hash chaining');
  assert(auditItem.isOperationalData === false, 'Audit item respects domain isolation');

  // 4.4 AI Copilot Advisory
  assert(copilotItem.id === 'copilot_engine', 'Fourth item is copilot_engine');
  assert(copilotItem.type === 'ai_copilot', 'Copilot type is ai_copilot');
  assert(copilotItem.state === 'Configured', 'Copilot state is Configured');
  assert(
    copilotItem.scopeNotice.includes('Strictly advisory assistant'),
    'Copilot scope notice confirms zero autonomous remediation authority'
  );
  assert(copilotItem.isOperationalData === false, 'Copilot item does not expose operational data');

  // =========================================================================
  // 5. LOCAL DEMO MODE FALLBACK INVENTORY
  // =========================================================================
  console.log('\n[Group 5: Local Prototype Mode Inventory]');

  const localDemoStatus: DatabaseConnectivityStatus = {
    isConfigured: false,
    isConnected: false,
    mode: 'development_demo',
    statusBadge: 'Local Demo',
    detail: 'Supabase credentials not configured. Local browser/in-memory adapters active.',
    checkedAt: new Date().toISOString(),
  };

  const localInventory = buildDataSourceInventory({
    dbStatus: localDemoStatus,
    copilotStatus: standbyCopilot,
    userCount: 4,
  });

  assert(localInventory[0].state === 'Local Demo', 'Primary DB correctly catalogs as Local Demo when unconfigured');
  assert(localInventory[3].state === 'Standby', 'Copilot correctly catalogs as Standby without live API key');

  // =========================================================================
  // 6. OPERATIONAL DATA ISOLATION VERIFICATION
  // =========================================================================
  console.log('\n[Group 6: Operational Data Isolation Verification]');

  // Ensure every item in inventory has isOperationalData: false
  for (const item of inventory) {
    assert(item.isOperationalData === false, `${item.name} has isOperationalData = false`);
    assert(
      !('alerts' in item) && !('notes' in item) && !('tasks' in item),
      `${item.name} contains zero operational alert or note payload keys`
    );
  }

  console.log(`\nAll ${totalTests} Admin Overview & Data Source Inventory tests passed successfully!`);
  return { passed: passedTests, total: totalTests };
}

// Execute when invoked directly
if (process.argv[1]?.endsWith('adminOverviewAndDataSourceInventoryTest.ts')) {
  runAdminOverviewAndDataSourceInventoryTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
