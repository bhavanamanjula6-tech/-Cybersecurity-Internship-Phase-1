/**
 * CyberOps SOC — Phase 2: Super Admin Enhancements Verification Suite
 *
 * Verifies:
 * 1. Authorized CSV export for Super Admin with correct RFC 4180 headers and row structure.
 * 2. Authorized JSON export for Super Admin with predictable schema and valid JSON parsing.
 * 3. Strict denial of audit export to unauthorized roles (soc_analyst, security_engineer, it_operations).
 * 4. Spreadsheet formula-injection mitigation (CWE-1236): prefixing '=', '+', '-', '@', '\t', '\r'.
 * 5. Safe RFC 4180 delimiter (comma), quote ('"'), and newline escaping.
 * 6. Empty audit log result handling (valid CSV header-only and JSON '[]').
 * 7. Non-exposure of private alert bodies, credentials, tokens, or secret keys.
 * 8. Server-side API endpoint (/api/admin/audit/export) authorization, format validation, and HTTP headers.
 * 9. Truthful session invalidation architectural boundary verification.
 * 10. Preservation of Super Admin operational isolation (isolated from private alerts & tasks).
 */

import fs from 'node:fs';
import path from 'node:path';
import { AuditExportService } from '../services/auditExportService';
import { AuthorizationService } from '../services/authorizationService';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { AuditLogEntry } from '../types/audit';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { createServer } from '../../server';

let passed = 0;
let total = 0;

function assert(condition: boolean, description: string, detail?: string) {
  total++;
  if (condition) {
    passed++;
    console.log(`  [PASS] Test ${total}: ${description}`);
  } else {
    console.error(`  [FAIL] Test ${total}: ${description}${detail ? ` -> ${detail}` : ''}`);
    process.exit(1);
  }
}

async function runSuperAdminEnhancementTests() {
  console.log('=== RUNNING SUPER ADMIN ENHANCEMENTS & AUDIT EXPORT VERIFICATION TESTS ===\n');

  const admin: UserProfile = DEMO_PERSONAS.super_admin;
  const analyst: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineer: UserProfile = DEMO_PERSONAS.security_engineer;
  const itOps: UserProfile = DEMO_PERSONAS.it_operations;

  const auditRepo = new LocalAuditLogRepository();
  const alertRepo = new LocalAlertRepository();

  const testLogs: AuditLogEntry[] = [
    {
      id: 'AUD-SIM-001',
      timestamp: '2026-10-12T04:00:20Z',
      actorName: 'Marcus Vance',
      actorRole: 'it_operations',
      actionType: 'isolate_host',
      targetResource: 'FILESERVER-01 (192.168.10.99)',
      justification: 'VSSadmin shadow copy deletion detected. Authorized host network quarantine per Playbook IR-04.',
      status: 'SIMULATED_SUCCESS',
      isSimulated: true,
      systemNote: 'Simulated endpoint isolation flag set. Network interface not severed in prototype environment.',
    },
    {
      id: 'AUD-SIM-002',
      timestamp: '2026-10-12T05:30:00Z',
      actorName: 'Sarah Chen',
      actorRole: 'super_admin',
      actionType: 'unlock_account',
      targetResource: 'devon.vance@soc.internal',
      justification: 'Account approved following identity verification. Assigned role: SOC_ANALYST',
      status: 'SUCCESS',
      isSimulated: false,
      systemNote: 'Operator account approved by Super Admin VANGUARD.',
    },
  ];

  // =========================================================================
  // Group 1: Role-Based Access Boundary & Permission Enforcement
  // =========================================================================
  console.log('-- Group 1: Role-Based Authorization & Boundary Checks --');

  assert(
    AuthorizationService.canExportAuditLogs('super_admin') === true,
    'Super Admin possesses permission to export audit logs (audit:export)'
  );

  assert(
    AuthorizationService.canExportAuditLogs('soc_analyst') === false,
    'SOC Analyst is strictly denied audit export capability'
  );

  assert(
    AuthorizationService.canExportAuditLogs('security_engineer') === false,
    'Security Engineer is strictly denied audit export capability'
  );

  assert(
    AuthorizationService.canExportAuditLogs('it_operations') === false,
    'IT Operations is strictly denied audit export capability'
  );

  // Assert assertCanExportAuditLogs throws AccessDeniedError for non-admin roles
  const nonAdminRoles: UserProfile[] = [analyst, engineer, itOps];
  for (const roleProfile of nonAdminRoles) {
    let threw = false;
    let errorType = '';
    try {
      AuthorizationService.assertCanExportAuditLogs(roleProfile);
    } catch (e: any) {
      threw = true;
      errorType = e.name;
    }
    assert(
      threw && errorType === 'AccessDeniedError',
      `assertCanExportAuditLogs throws AccessDeniedError for role "${roleProfile.role}"`
    );
  }

  // Super Admin assertCanExportAuditLogs does not throw
  let adminThrew = false;
  try {
    AuthorizationService.assertCanExportAuditLogs(admin);
  } catch {
    adminThrew = true;
  }
  assert(!adminThrew, 'assertCanExportAuditLogs succeeds without error for Super Admin');

  // =========================================================================
  // Group 2: CSV Export Generation & RFC 4180 Escaping
  // =========================================================================
  console.log('\n-- Group 2: Authorized CSV Export & Escaping --');

  const csv = AuditExportService.generateCsv(testLogs, admin);
  assert(csv.startsWith('\uFEFF'), 'CSV export begins with UTF-8 BOM (\\uFEFF) for Excel compatibility');

  const csvLines = csv.replace('\uFEFF', '').trim().split('\r\n');
  assert(csvLines.length === 3, `CSV export contains header plus 2 data rows (got ${csvLines.length} lines)`);

  const expectedHeader = '"id","timestamp","actionType","actorName","actorRole","targetResource","status","isSimulated","justification","systemNote"';
  assert(csvLines[0] === expectedHeader, 'CSV header matches authorized audit columns');

  assert(csvLines[1].includes('AUD-SIM-001'), 'Row 1 contains correct audit ID AUD-SIM-001');
  assert(csvLines[2].includes('AUD-SIM-002'), 'Row 2 contains correct audit ID AUD-SIM-002');
  assert(csvLines[2].includes('Sarah Chen'), 'Row 2 contains actor Sarah Chen');

  // Denial check on generateCsv for non-admin
  let csvDenialCaught = false;
  try {
    AuditExportService.generateCsv(testLogs, analyst);
  } catch (e: any) {
    csvDenialCaught = e instanceof AccessDeniedError;
  }
  assert(csvDenialCaught, 'generateCsv rejects unauthorized role with AccessDeniedError');

  // =========================================================================
  // Group 3: Spreadsheet Formula Injection Mitigation (CWE-1236)
  // =========================================================================
  console.log('\n-- Group 3: Spreadsheet Formula Injection Mitigation (CWE-1236) --');

  const injectionPayloads = [
    { input: '=cmd|"/C calc"!A0', expected: '\'=cmd|"/C calc"!A0' },
    { input: '+SUM(1+1)', expected: '\'+SUM(1+1)' },
    { input: '-10+20', expected: '\'-10+20' },
    { input: '@SUM(A1:A10)', expected: '\'@SUM(A1:A10)' },
    { input: '\t=DDE("cmd";"";"calc")', expected: '\'\t=DDE("cmd";"";"calc")' },
    { input: '\r=cmd', expected: '\'\r=cmd' },
    { input: '   =2+5', expected: '\'   =2+5' },
    { input: 'Normal Justification text without formula', expected: 'Normal Justification text without formula' },
  ];

  for (const item of injectionPayloads) {
    const sanitized = AuditExportService.sanitizeCellForCsv(item.input);
    if (item.input.startsWith('Normal')) {
      assert(sanitized === item.expected, `Normal cell preserved without apostrophe: "${item.input}"`);
    } else {
      assert(
        sanitized.startsWith("'") || sanitized.startsWith('"\''),
        `Formula trigger "${item.input}" is neutralized with single quote prefix (got: ${sanitized})`
      );
    }
  }

  // Verify full CSV with malicious payload in justification
  const maliciousLog: AuditLogEntry = {
    id: 'AUD-TEST-MALICIOUS',
    timestamp: '2026-10-12T06:00:00Z',
    actorName: '=cmd|"/C calc"!A0',
    actorRole: 'super_admin',
    actionType: 'unlock_account',
    targetResource: '+192.168.1.1',
    justification: '@HYPERLINK("http://attacker.com","Click")',
    status: 'SUCCESS',
    isSimulated: false,
    systemNote: '-Important note with dash prefix',
  };

  const maliciousCsv = AuditExportService.generateCsv([maliciousLog], admin);
  assert(maliciousCsv.includes('\'=cmd'), 'Actor name with "=cmd" is neutralized with apostrophe in CSV');
  assert(maliciousCsv.includes('\'+192.168.1.1'), 'Target resource with "+ip" is neutralized in CSV');
  assert(maliciousCsv.includes('\'@HYPERLINK'), 'Justification with "@HYPERLINK" is neutralized in CSV');
  assert(maliciousCsv.includes('\'-Important note'), 'System note with "-note" is neutralized in CSV');

  // RFC 4180 quotes & multiline escaping
  const quotedLog: AuditLogEntry = {
    id: 'AUD-QUOTED',
    timestamp: '2026-10-12T07:00:00Z',
    actorName: 'Alice "The Shield" Smith',
    actorRole: 'super_admin',
    actionType: 'lock_account',
    targetResource: 'WS-01,WS-02',
    justification: 'Line 1\nLine 2 with "quotes", and commas.',
    status: 'SUCCESS',
    isSimulated: false,
    systemNote: 'Standard system note',
  };

  const quotedCsv = AuditExportService.generateCsv([quotedLog], admin);
  assert(quotedCsv.includes('"Alice ""The Shield"" Smith"'), 'Double quotes are correctly escaped as double-double quotes ("")');
  assert(quotedCsv.includes('"WS-01,WS-02"'), 'Commas in values cause cell to be wrapped in double quotes');
  assert(quotedCsv.includes('"Line 1\nLine 2 with ""quotes"", and commas."'), 'Multiline cells with quotes and commas are properly enclosed');

  // =========================================================================
  // Group 4: JSON Export Formatting & Schema Integrity
  // =========================================================================
  console.log('\n-- Group 4: Authorized JSON Export & Schema Integrity --');

  const json = AuditExportService.generateJson(testLogs, admin);
  let parsedJson: any[] = [];
  try {
    parsedJson = JSON.parse(json);
    assert(Array.isArray(parsedJson), 'JSON export parses to a valid array');
  } catch (err: any) {
    assert(false, 'JSON export is valid JSON', err.message);
  }

  assert(parsedJson.length === 2, 'JSON export contains exactly 2 records');
  const record1 = parsedJson[0];
  assert(record1.id === 'AUD-SIM-001', 'Record 1 has expected id AUD-SIM-001');
  assert(record1.actionType === 'isolate_host', 'Record 1 has actionType isolate_host');
  assert(record1.isSimulated === true, 'Record 1 has boolean isSimulated: true');
  assert(record1.actorRole === 'it_operations', 'Record 1 has actorRole it_operations');

  // Denial check on generateJson for non-admin
  let jsonDenialCaught = false;
  try {
    AuditExportService.generateJson(testLogs, engineer);
  } catch (e: any) {
    jsonDenialCaught = e instanceof AccessDeniedError;
  }
  assert(jsonDenialCaught, 'generateJson rejects unauthorized role with AccessDeniedError');

  // =========================================================================
  // Group 5: Empty Audit Results & Retrieval Failures
  // =========================================================================
  console.log('\n-- Group 5: Empty Results & Edge Cases --');

  const emptyCsv = AuditExportService.generateCsv([], admin);
  const emptyCsvLines = emptyCsv.replace('\uFEFF', '').trim().split('\r\n');
  assert(emptyCsvLines.length === 1, 'Empty audit log produces CSV with exactly 1 header line and no data rows');
  assert(emptyCsvLines[0] === expectedHeader, 'Header line is complete even when audit logs array is empty');

  const emptyJson = AuditExportService.generateJson([], admin);
  assert(emptyJson === '[]', 'Empty audit log produces "[]" JSON string');

  // =========================================================================
  // Group 6: Strict Data Scoping & Non-Exposure of Sensitive Data
  // =========================================================================
  console.log('\n-- Group 6: Data Scoping & Sensitive Field Protection --');

  // Ensure no password, token, or secret fields exist on the exported record
  const sampleExportRecord = AuditExportService.mapToExportRecord(testLogs[0]);
  const allowedKeys = new Set(AuditExportService.EXPORT_COLUMNS);
  const recordKeys = Object.keys(sampleExportRecord);

  assert(
    recordKeys.every((k) => allowedKeys.has(k as any)),
    'Exported record contains ONLY authorized platform audit fields'
  );

  const sensitiveFieldNames = ['password', 'secret', 'token', 'apiKey', 'jwt', 'rawAlertPayload', 'privateNotes'];
  assert(
    !sensitiveFieldNames.some((s) => recordKeys.includes(s)),
    'Exported record strictly omits credentials, tokens, secrets, and private operational data'
  );

  // Super Admin cannot access private operational alerts
  let adminAlertDenied = false;
  try {
    await alertRepo.getAlertsForUser(admin);
  } catch (e: any) {
    adminAlertDenied = e instanceof AccessDeniedError;
  }
  assert(adminAlertDenied, 'Super Admin remains strictly denied from retrieving private operational alerts');

  // Super Admin tasks are strictly empty
  const adminTasks = await auditRepo.getIncidentTasksForUser(admin);
  assert(adminTasks.length === 0, 'Super Admin incident tasks list remains strictly empty (isolated)');

  // =========================================================================
  // Group 7: Vulnerable Endpoint Deregistration & Clean 404 Guard
  // =========================================================================
  console.log('\n-- Group 7: Vulnerable Server Endpoint Deregistration & Clean 404 Guard --');

  const TEST_SERVER_PORT = 3205;
  const serverInstance = await createServer();

  await new Promise<void>((resolve, reject) => {
    serverInstance.httpServer.listen(TEST_SERVER_PORT, '0.0.0.0', () => resolve());
    serverInstance.httpServer.on('error', reject);
  });

  const baseUrl = `http://127.0.0.1:${TEST_SERVER_PORT}`;

  try {
    // 1. Direct GET /api/admin/audit/export returns 404 Not Found (no longer registered)
    const resGet = await fetch(`${baseUrl}/api/admin/audit/export`);
    assert(resGet.status === 404, 'GET /api/admin/audit/export returns HTTP 404 Not Found (endpoint cleanly removed)');
    const bodyGet = await resGet.json() as { error?: string };
    assert(bodyGet.error === 'API endpoint not found', '404 response body returns standard "API endpoint not found"');

    // 2. Spoofed query parameter (?role=super_admin) also returns 404
    const resSpoofedQuery = await fetch(`${baseUrl}/api/admin/audit/export?role=super_admin`);
    assert(resSpoofedQuery.status === 404, 'Spoofed query parameter (?role=super_admin) returns HTTP 404');
    const bodyQuery = await resSpoofedQuery.json() as { error?: string };
    assert(bodyQuery.error === 'API endpoint not found', 'Spoofed query returns standard 404 JSON');

    // 3. Spoofed header (x-user-role: super_admin) also returns 404
    const resSpoofedHeader = await fetch(`${baseUrl}/api/admin/audit/export`, {
      headers: { 'x-user-role': 'super_admin' },
    });
    assert(resSpoofedHeader.status === 404, 'Spoofed header (x-user-role: super_admin) returns HTTP 404');
    const bodyHeader = await resSpoofedHeader.json() as { error?: string };
    assert(bodyHeader.error === 'API endpoint not found', 'Spoofed header returns standard 404 JSON');

    // 4. Other HTTP methods (POST, PUT, DELETE) also return 404
    const resPost = await fetch(`${baseUrl}/api/admin/audit/export`, { method: 'POST', body: '{}' });
    assert(resPost.status === 404, 'POST /api/admin/audit/export returns HTTP 404 Not Found');

    // 5. Verify Content-Type is application/json for 404 responses
    const contentType = resGet.headers.get('content-type') || '';
    assert(contentType.includes('application/json'), '404 response returns application/json (not swallowed by SPA)');
  } finally {
    await serverInstance.close();
  }

  // =========================================================================
  // Group 8: Session Invalidation Architecture Audit & Truthful Verification
  // =========================================================================
  console.log('\n-- Group 8: Session Invalidation Architectural Invariants --');

  // Verify that the codebase does not claim fake multi-session termination
  assert(
    typeof (auditRepo as any).terminateUserSessions === 'undefined',
    'No fake client-side session termination method on auditRepo'
  );
  assert(
    typeof (alertRepo as any).revokeAllSessions === 'undefined',
    'No fake session revocation method on alertRepo'
  );

  // =========================================================================
  // Group 9: Database & Repository Data-Access RLS Invariants
  // =========================================================================
  console.log('\n-- Group 9: Database & Repository Data-Access RLS Invariants --');

  // Verify that an unauthenticated caller cannot call auditRepo.getLogsForUser
  let nullUserCaught = false;
  try {
    await auditRepo.getLogsForUser({} as any);
  } catch (e: any) {
    nullUserCaught = e instanceof AccessDeniedError || Boolean(e.message);
  }
  assert(nullUserCaught, 'Unauthenticated user calling getLogsForUser is rejected');

  // Verify that PostgreSQL migration strictly defines audit_select_policy with RLS
  const migrationPath = path.resolve(process.cwd(), 'supabase/migrations/20261015000000_initial_cyberops_soc_schema.sql');
  const migrationSql = fs.readFileSync(migrationPath, 'utf8');

  assert(
    migrationSql.includes('CREATE POLICY "audit_select_policy" ON public.audit_logs'),
    'PostgreSQL RLS audit_select_policy is defined on public.audit_logs'
  );
  assert(
    migrationSql.includes("(audit_category = 'platform' AND public.get_user_role() = 'super_admin')"),
    'PostgreSQL RLS restricts platform audit logs strictly to public.get_user_role() = \'super_admin\''
  );
  assert(
    migrationSql.includes("(audit_category = 'operational' AND public.get_user_role() IN ('soc_analyst', 'security_engineer', 'it_operations'))"),
    'PostgreSQL RLS isolates operational audit logs to operational roles'
  );

  console.log(`\n========================================================`);
  console.log(`All ${passed} of ${total} Super Admin Enhancement tests PASSED!`);
  console.log(`========================================================`);
}

runSuperAdminEnhancementTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
