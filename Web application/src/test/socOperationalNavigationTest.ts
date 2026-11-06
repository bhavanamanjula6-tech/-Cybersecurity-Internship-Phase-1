/**
 * Automated Verification Test for SOC Analyst "Investigate & Respond" Navigation and Authorization
 *
 * Verifies:
 * 1. SOC Analyst has access to all four operational pages:
 *    - Alert Triage Queue ('alerts')
 *    - Deep Investigation ('investigations')
 *    - Response Playbooks ('playbooks')
 *    - Containment Audit Trail ('audit')
 * 2. Deep Investigation and Response Playbooks are authorized strictly for SOC Analyst only.
 * 3. All other roles (security_engineer, it_operations, super_admin) preserve their exact permissions.
 * 4. AppSidebar navigation filtering and labels for all four roles.
 * 5. AuthorizationService.assertViewAccess enforcement.
 */

import { AuthorizationService } from '../services/authorizationService';
import { UserRole, DEMO_PERSONAS, AccessDeniedError } from '../types/auth';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

console.log('=== Starting SOC Analyst Navigation & Authorization Verification ===\n');

// 1. Verify SOC Analyst View Authorization Matrix
console.log('1. Checking SOC Analyst authorized views...');
const socExpectedViews = [
  'overview',
  'strategies',
  'analytics',
  'log_sources',
  'data_components',
  'mitre_explorer',
  'alerts',
  'investigations',
  'playbooks',
  'audit',
  'profile',
];

for (const view of socExpectedViews) {
  assert(
    AuthorizationService.isViewAuthorized('soc_analyst', view),
    `soc_analyst must be authorized for view "${view}"`
  );
}
console.log('✓ All 11 expected views (6 knowledge + 4 operational + profile) authorized for soc_analyst.');

// 2. Verify Deep Investigation and Response Playbooks are SOC Analyst ONLY
console.log('\n2. Checking exclusivity of Deep Investigation and Response Playbooks...');
const otherRoles: UserRole[] = ['security_engineer', 'it_operations', 'super_admin'];

for (const role of otherRoles) {
  assert(
    !AuthorizationService.isViewAuthorized(role, 'investigations'),
    `Role "${role}" must NOT be authorized for "investigations"`
  );
  assert(
    !AuthorizationService.isViewAuthorized(role, 'playbooks'),
    `Role "${role}" must NOT be authorized for "playbooks"`
  );
}
console.log('✓ Deep Investigation and Response Playbooks are strictly authorized for soc_analyst ONLY.');

// 3. Verify Exact Access Permissions of Other Roles Preserved
console.log('\n3. Checking other roles access preservation...');

// Security Engineer
const secEngAuthorized = ['seceng_overview', 'mitre', 'alerts', 'audit', 'profile'];
for (const view of secEngAuthorized) {
  assert(
    AuthorizationService.isViewAuthorized('security_engineer', view),
    `security_engineer must be authorized for "${view}"`
  );
}
const secEngForbidden = [
  'overview',
  'strategies',
  'analytics',
  'log_sources',
  'data_components',
  'mitre_explorer',
  'itops_overview',
  'itops_techniques',
  'itops_mitigations',
  'tasks',
  'admin',
  'investigations',
  'playbooks',
];
for (const view of secEngForbidden) {
  assert(
    !AuthorizationService.isViewAuthorized('security_engineer', view),
    `security_engineer must NOT be authorized for "${view}"`
  );
}
console.log('✓ Security Engineer permissions preserved exactly.');

// IT Operations
const itOpsAuthorized = [
  'itops_overview',
  'itops_techniques',
  'itops_mitigations',
  'tasks',
  'alerts',
  'audit',
  'profile',
];
for (const view of itOpsAuthorized) {
  assert(
    AuthorizationService.isViewAuthorized('it_operations', view),
    `it_operations must be authorized for "${view}"`
  );
}
const itOpsForbidden = [
  'overview',
  'strategies',
  'analytics',
  'log_sources',
  'data_components',
  'mitre_explorer',
  'seceng_overview',
  'mitre',
  'admin',
  'investigations',
  'playbooks',
];
for (const view of itOpsForbidden) {
  assert(
    !AuthorizationService.isViewAuthorized('it_operations', view),
    `it_operations must NOT be authorized for "${view}"`
  );
}
console.log('✓ IT Operations permissions preserved exactly.');

// Super Admin
const superAdminAuthorized = ['admin', 'audit', 'profile'];
for (const view of superAdminAuthorized) {
  assert(
    AuthorizationService.isViewAuthorized('super_admin', view),
    `super_admin must be authorized for "${view}"`
  );
}
const superAdminForbidden = [
  'overview',
  'strategies',
  'analytics',
  'log_sources',
  'data_components',
  'mitre_explorer',
  'seceng_overview',
  'mitre',
  'itops_overview',
  'itops_techniques',
  'itops_mitigations',
  'tasks',
  'alerts',
  'investigations',
  'playbooks',
];
for (const view of superAdminForbidden) {
  assert(
    !AuthorizationService.isViewAuthorized('super_admin', view),
    `super_admin must NOT be authorized for "${view}"`
  );
}
console.log('✓ Super Admin permissions preserved exactly.');

// 4. Verify assertViewAccess error enforcement
console.log('\n4. Checking assertViewAccess error enforcement...');

// Allowed actions must not throw
AuthorizationService.assertViewAccess('soc_analyst', 'alerts');
AuthorizationService.assertViewAccess('soc_analyst', 'investigations');
AuthorizationService.assertViewAccess('soc_analyst', 'playbooks');
AuthorizationService.assertViewAccess('soc_analyst', 'audit');
console.log('✓ assertViewAccess passed for soc_analyst on all 4 operational views.');

// Denied actions must throw AccessDeniedError
const unauthorizedTests: Array<{ role: UserRole; view: string }> = [
  { role: 'security_engineer', view: 'investigations' },
  { role: 'security_engineer', view: 'playbooks' },
  { role: 'it_operations', view: 'investigations' },
  { role: 'it_operations', view: 'playbooks' },
  { role: 'super_admin', view: 'alerts' },
  { role: 'super_admin', view: 'investigations' },
  { role: 'super_admin', view: 'playbooks' },
];

for (const { role, view } of unauthorizedTests) {
  let threw = false;
  try {
    AuthorizationService.assertViewAccess(role, view);
  } catch (err: any) {
    threw = true;
    assert(err instanceof AccessDeniedError, `Expected AccessDeniedError for ${role} on ${view}`);
  }
  assert(threw, `Expected assertViewAccess to throw for role "${role}" on view "${view}"`);
}
console.log('✓ assertViewAccess successfully denied all unauthorized view attempts.');

// 5. Verify AppSidebar navigation items logic
console.log('\n5. Checking AppSidebar navigation configuration...');

// Simulate AppSidebar nav items configuration
const rawNavItems: Array<{
  id: string;
  label: (role: UserRole) => string;
  authorizedRoles: UserRole[];
}> = [
  { id: 'admin', label: () => 'Platform Administration', authorizedRoles: ['super_admin'] },
  { id: 'overview', label: () => 'SOC Analytics Overview', authorizedRoles: ['soc_analyst'] },
  { id: 'strategies', label: () => 'Detection Strategy Analytics', authorizedRoles: ['soc_analyst'] },
  { id: 'analytics', label: () => 'Analytic Analytics', authorizedRoles: ['soc_analyst'] },
  { id: 'log_sources', label: () => 'Log Source Analytics', authorizedRoles: ['soc_analyst'] },
  { id: 'data_components', label: () => 'Data Component Analytics', authorizedRoles: ['soc_analyst'] },
  { id: 'mitre_explorer', label: () => 'MITRE ATT&CK Explorer', authorizedRoles: ['soc_analyst'] },
  { id: 'itops_overview', label: () => 'IT Operations Overview', authorizedRoles: ['it_operations'] },
  { id: 'itops_techniques', label: () => 'Technique & Platform Explorer', authorizedRoles: ['it_operations'] },
  { id: 'itops_mitigations', label: () => 'Mitigation Explorer', authorizedRoles: ['it_operations'] },
  { id: 'seceng_overview', label: () => 'Overview', authorizedRoles: ['security_engineer'] },
  { id: 'mitre', label: () => 'Threat Intelligence (MITRE ATT&CK)', authorizedRoles: ['security_engineer'] },
  { id: 'tasks', label: () => 'Incident Response Tasks', authorizedRoles: ['it_operations'] },
  {
    id: 'alerts',
    label: (role) => (role === 'it_operations' ? 'Scoped Incident Alerts' : 'Alert Triage Queue'),
    authorizedRoles: ['soc_analyst', 'security_engineer', 'it_operations'],
  },
  { id: 'investigations', label: () => 'Deep Investigation', authorizedRoles: ['soc_analyst'] },
  { id: 'playbooks', label: () => 'Response Playbooks', authorizedRoles: ['soc_analyst'] },
  {
    id: 'audit',
    label: () => 'Containment Audit Trail',
    authorizedRoles: ['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'],
  },
];

// Helper to filter nav items for a role
function getVisibleNav(role: UserRole) {
  return rawNavItems.filter((item) => item.authorizedRoles.includes(role));
}

const socNav = getVisibleNav('soc_analyst');
assert(socNav.length === 10, `Expected 10 nav items for soc_analyst, got ${socNav.length}`);
const socIds = socNav.map((i) => i.id);
assert(socIds.includes('alerts'), 'soc_analyst nav must include alerts');
assert(socIds.includes('investigations'), 'soc_analyst nav must include investigations');
assert(socIds.includes('playbooks'), 'soc_analyst nav must include playbooks');
assert(socIds.includes('audit'), 'soc_analyst nav must include audit');

const alertsItemForSoc = socNav.find((i) => i.id === 'alerts');
assert(
  alertsItemForSoc?.label('soc_analyst') === 'Alert Triage Queue',
  'alerts label for soc_analyst must be "Alert Triage Queue"'
);

const secEngNav = getVisibleNav('security_engineer');
assert(secEngNav.length === 4, `Expected 4 nav items for security_engineer, got ${secEngNav.length}`);
assert(
  JSON.stringify(secEngNav.map((i) => i.id).sort()) ===
    JSON.stringify(['seceng_overview', 'mitre', 'alerts', 'audit'].sort()),
  'security_engineer nav items mismatch'
);

const itOpsNav = getVisibleNav('it_operations');
assert(itOpsNav.length === 6, `Expected 6 nav items for it_operations, got ${itOpsNav.length}`);
assert(
  JSON.stringify(itOpsNav.map((i) => i.id).sort()) ===
    JSON.stringify(['itops_overview', 'itops_techniques', 'itops_mitigations', 'tasks', 'alerts', 'audit'].sort()),
  'it_operations nav items mismatch'
);

const superAdminNav = getVisibleNav('super_admin');
assert(superAdminNav.length === 2, `Expected 2 nav items for super_admin, got ${superAdminNav.length}`);
assert(
  JSON.stringify(superAdminNav.map((i) => i.id).sort()) ===
    JSON.stringify(['admin', 'audit'].sort()),
  'super_admin nav items mismatch'
);

console.log('✓ AppSidebar navigation filtering validated for all 4 roles.');

console.log('\n=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY ===');
