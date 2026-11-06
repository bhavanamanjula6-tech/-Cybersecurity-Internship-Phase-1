/**
 * CyberOps SOC — IT Operations Endpoint & Host Inventory Verification Suite
 *
 * Verifies:
 * 1. Endpoint aggregation from existing authorized application records (assigned tasks and scoped alerts).
 * 2. Proper consolidation of multiple tasks targeting the same host.
 * 3. Honest non-fabrication of missing host attributes (displays "Not available" / "Not recorded in telemetry").
 * 4. Strict role-scoping: IT Operations sees ONLY endpoints linked to its assigned tasks; tasks assigned
 *    to security_engineer or soc_analyst are strictly excluded.
 * 5. Strict Super Admin operational isolation: Super Admin receives zero endpoint records.
 * 6. Provenance and clear distinction between directly observed data vs. inferred information.
 * 7. Containment status truthfulness derived strictly from stored audit logs and task lifecycle state.
 */

import { IncidentTask, AuditLogEntry } from '../types/audit';
import { SecurityAlert } from '../types/alert';
import { UserProfile, DEMO_PERSONAS } from '../types/auth';
import {
  buildEndpointInventory,
  EndpointRecord,
} from '../services/endpointInventoryService';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';

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

export async function runITOperationsEndpointInventoryTests(): Promise<{ passed: number; total: number }> {
  console.log('--- IT Operations Endpoint & Host Inventory Test Suite ---');

  const itUser: UserProfile = DEMO_PERSONAS.it_operations;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;
  const secEngUser: UserProfile = DEMO_PERSONAS.security_engineer;

  // Sample tasks reflecting production dataset
  const sampleTasks: IncidentTask[] = [
    {
      id: 'TSK-2026-001',
      title: 'Verify File Server Offline Snapshot Integrity',
      description: 'Ensure offline storage backups for FILESERVER-01 are uncorrupted.',
      assignedRole: 'it_operations',
      status: 'pending',
      priority: 'critical',
      createdAt: '2026-10-12T04:02:00Z',
      targetAsset: 'FILESERVER-01',
      suggestedActionType: 'isolate_host',
      associatedAlertId: 'ALT-2026-1046',
    },
    {
      id: 'TSK-2026-002',
      title: 'Revoke and Reset Compromised Service Account Kerberos Ticket',
      description: 'Service account DOMAIN\\svc_backup observed initiating unauthorized WMI.',
      assignedRole: 'it_operations',
      status: 'in_progress',
      priority: 'high',
      createdAt: '2026-10-12T04:35:00Z',
      targetAsset: 'PRIMARY-DC',
      suggestedActionType: 'lock_account',
      associatedAlertId: 'ALT-2026-1047',
    },
    {
      id: 'TSK-2026-003',
      title: 'Configure Edge Firewall Rate Limiting for DMZ Proxy',
      description: 'Implement connection threshold per IP.',
      assignedRole: 'security_engineer', // Assigned to security engineer, NOT IT Ops!
      status: 'pending',
      priority: 'medium',
      createdAt: '2026-10-12T05:12:00Z',
      targetAsset: 'WEB-PROXY-DMZ',
      suggestedActionType: 'block_ip',
      associatedAlertId: 'ALT-2026-1045',
    },
  ];

  // Scoped alerts: only ALT-2026-1046 and ALT-2026-1047 for IT Operations
  const itScopedAlerts = INITIAL_SYNTHETIC_ALERTS.filter(
    (a) => a.id === 'ALT-2026-1046' || a.id === 'ALT-2026-1047'
  );

  const sampleAuditLogs: AuditLogEntry[] = [
    {
      id: 'AUD-SIM-001',
      timestamp: '2026-10-12T04:00:20Z',
      actorName: 'Marcus Vance',
      actorRole: 'it_operations',
      actionType: 'isolate_host',
      targetResource: 'FILESERVER-01 (192.168.10.99)',
      justification: 'VSSadmin shadow copy deletion detected. Authorized host network quarantine.',
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: 'ALT-2026-1046',
      isSimulated: true,
      systemNote: 'Simulated endpoint isolation flag set.',
    },
  ];

  // =========================================================================
  // 1. ENDPOINT AGGREGATION & CONSOLIDATION
  // =========================================================================
  console.log('\n[Group 1: Endpoint Aggregation from Authorized Data]');

  const itInventory = buildEndpointInventory({
    tasks: sampleTasks,
    scopedAlerts: itScopedAlerts,
    auditLogs: sampleAuditLogs,
    currentUser: itUser,
  });

  assert(itInventory.length === 2, 'IT Operations inventory contains exactly 2 authorized endpoints');

  const fileserver = itInventory.find((e) => e.hostname === 'FILESERVER-01');
  assert(Boolean(fileserver), 'FILESERVER-01 exists in inventory');
  assert(fileserver?.ipAddress === '192.168.10.99', 'FILESERVER-01 IP address correctly populated from alert evidence');
  assert(fileserver?.fqdn === 'fs-01.corp.internal', 'FILESERVER-01 FQDN correctly populated from alert evidence');
  assert(fileserver?.associatedTasks.length === 1, 'FILESERVER-01 has 1 associated task');
  assert(fileserver?.associatedTasks[0].taskId === 'TSK-2026-001', 'Associated task ID is TSK-2026-001');
  assert(fileserver?.associatedAlerts.length === 1, 'FILESERVER-01 has 1 linked alert');
  assert(fileserver?.associatedAlerts[0].alertId === 'ALT-2026-1046', 'Associated alert ID is ALT-2026-1046');

  const primaryDc = itInventory.find((e) => e.hostname === 'PRIMARY-DC');
  assert(Boolean(primaryDc), 'PRIMARY-DC exists in inventory');
  assert(primaryDc?.ipAddress === '192.168.10.5', 'PRIMARY-DC IP address correctly populated from alert evidence');
  assert(primaryDc?.fqdn === 'dc-01.corp.internal', 'PRIMARY-DC FQDN correctly populated from alert evidence');
  assert(primaryDc?.associatedTasks[0].taskId === 'TSK-2026-002', 'PRIMARY-DC linked to TSK-2026-002');

  // Test Task Consolidation: Add a second task targeting FILESERVER-01
  const multiTaskSample: IncidentTask[] = [
    ...sampleTasks,
    {
      id: 'TSK-2026-004',
      title: 'Perform Forensic Memory Dump on FILESERVER-01',
      description: 'Collect volatile memory image before network restoration.',
      assignedRole: 'it_operations',
      status: 'pending',
      priority: 'high',
      createdAt: '2026-10-12T04:40:00Z',
      targetAsset: 'FILESERVER-01',
      suggestedActionType: 'collect_forensics',
    },
  ];

  const consolidatedInventory = buildEndpointInventory({
    tasks: multiTaskSample,
    scopedAlerts: itScopedAlerts,
    auditLogs: sampleAuditLogs,
    currentUser: itUser,
  });

  const consolidatedFileserver = consolidatedInventory.find((e) => e.hostname === 'FILESERVER-01');
  assert(
    consolidatedFileserver?.associatedTasks.length === 2,
    'Multiple tasks targeting FILESERVER-01 are consolidated under single endpoint record'
  );
  assert(
    consolidatedFileserver?.associatedTasks.some((t) => t.taskId === 'TSK-2026-004') === true,
    'Consolidated endpoint includes secondary task TSK-2026-004'
  );

  // =========================================================================
  // 2. NON-FABRICATION & HANDLING OF MISSING ATTRIBUTES
  // =========================================================================
  console.log('\n[Group 2: Non-Fabrication of Missing Attributes]');

  // Task with targetAsset only, no linked alert
  const unlinkedTask: IncidentTask = {
    id: 'TSK-2026-005',
    title: 'Isolate Unregistered Test Machine RND-TEST-09',
    description: 'Ad-hoc containment request without telemetry correlation.',
    assignedRole: 'it_operations',
    status: 'pending',
    priority: 'low',
    createdAt: '2026-10-12T06:00:00Z',
    targetAsset: 'RND-TEST-09',
  };

  const unlinkedInventory = buildEndpointInventory({
    tasks: [unlinkedTask],
    scopedAlerts: [],
    currentUser: itUser,
  });

  const unlinkedEndpoint = unlinkedInventory.find((e) => e.hostname === 'RND-TEST-09');
  assert(Boolean(unlinkedEndpoint), 'Unlinked asset RND-TEST-09 appears in inventory from task');
  assert(
    unlinkedEndpoint?.ipAddress === 'Not available',
    'Missing IP is honestly labeled "Not available" (no fake IP fabricated)'
  );
  assert(
    unlinkedEndpoint?.fqdn === 'Not available',
    'Missing FQDN is honestly labeled "Not available"'
  );
  assert(
    unlinkedEndpoint?.osDetails === 'Not recorded in telemetry',
    'Missing OS is honestly labeled "Not recorded in telemetry"'
  );
  assert(
    unlinkedEndpoint?.osIsInferred === false,
    'osIsInferred is false when OS is completely missing'
  );

  // =========================================================================
  // 3. ROLE SCOPING & CROSS-ROLE LEAK PREVENTION
  // =========================================================================
  console.log('\n[Group 3: Role Scoping & Isolation]');

  // Verify that TSK-2026-003 (assigned to security_engineer, targetAsset: WEB-PROXY-DMZ) is NOT in IT Operations inventory!
  const proxyEndpoint = itInventory.find((e) => e.hostname.includes('PROXY') || e.hostname === 'WEB-PROXY-DMZ');
  assert(
    proxyEndpoint === undefined,
    'Security Engineer task (WEB-PROXY-DMZ) is strictly excluded from IT Operations endpoint inventory'
  );

  // Verify that unassigned alerts (e.g. ALT-2026-1049 targeting WORKSTATION-CORP-14) are NOT in IT Operations inventory!
  const workstation = itInventory.find((e) => e.hostname.includes('WORKSTATION-CORP-14'));
  assert(
    workstation === undefined,
    'Unassigned alert host WORKSTATION-CORP-14 is strictly excluded from IT Operations endpoint inventory'
  );

  // =========================================================================
  // 4. SUPER ADMIN OPERATIONAL ISOLATION
  // =========================================================================
  console.log('\n[Group 4: Super Admin Operational Isolation]');

  const adminInventory = buildEndpointInventory({
    tasks: sampleTasks,
    scopedAlerts: INITIAL_SYNTHETIC_ALERTS,
    auditLogs: sampleAuditLogs,
    currentUser: adminUser,
  });

  assert(
    adminInventory.length === 0,
    'Super Admin receives strictly 0 endpoint records (Domain C isolation enforced)'
  );

  // =========================================================================
  // 5. DATA PROVENANCE & CONTAINMENT TRUTHFULNESS
  // =========================================================================
  console.log('\n[Group 5: Data Provenance & Containment Truthfulness]');

  assert(
    fileserver?.containmentStatus === 'Simulated Isolated',
    'FILESERVER-01 containment status is "Simulated Isolated" derived from audit log AUD-SIM-001'
  );
  assert(
    Boolean(fileserver?.containmentRationale.includes('Simulated host quarantine executed per audit record AUD-SIM-001')),
    'Containment rationale cites exact audit log and justification'
  );

  assert(
    primaryDc?.containmentStatus === 'Active / Standard Network',
    'PRIMARY-DC containment status is "Active / Standard Network" (lock_account task does not isolate host)'
  );

  assert(
    fileserver?.osIsInferred === true,
    'osIsInferred is true for FILESERVER-01 (inferred from Windows Security Event Log)'
  );
  assert(
    Boolean(fileserver?.osDetails.includes('Inferred from Windows Event Log')),
    'OS label explicitly discloses inference from Windows Event Log'
  );

  assert(
    Boolean(fileserver?.provenance.includes('Synthetic Demonstration Data')),
    'Provenance documents synthetic demonstration dataset source'
  );

  console.log(`\nAll ${totalTests} IT Operations Endpoint Inventory tests passed successfully!`);
  return { passed: passedTests, total: totalTests };
}

// Execute when invoked directly
if (process.argv[1]?.endsWith('itOperationsEndpointInventoryTest.ts')) {
  runITOperationsEndpointInventoryTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
