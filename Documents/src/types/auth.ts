/**
 * Authentication and authorization types for the SOC platform.
 * Defines operational roles, platform administration role, granular capabilities, and test personas.
 */

export type UserRole = 'soc_analyst' | 'security_engineer' | 'it_operations' | 'super_admin';

export type AccountStatus = 'pending' | 'approved' | 'disabled' | 'rejected';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  callsign: string;
  avatarUrl?: string;
  title: string;
  accountStatus?: AccountStatus;
  approvedBy?: string;
  approvedAt?: string;
  createdAt?: string;
  lastAuditId?: string;
}

export type Permission =
  | 'alert:read'
  | 'alert:triage'
  | 'alert:escalate'
  | 'alert:add_note'
  | 'alert:read_scoped_only'
  | 'notes:read_private'
  | 'mitre:read'
  | 'mitre:analyze_coverage'
  | 'incident:read'
  | 'incident:update'
  | 'action:propose'
  | 'action:authorize_simulated'
  | 'audit:read'
  | 'audit:export'
  | 'platform:admin'
  | 'platform:health_read'
  | 'recommendation:create'
  | 'recommendation:read'
  | 'recommendation:review'
  | 'recommendation:update'
  | 'recommendation:validate';

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  soc_analyst: [
    'alert:read',
    'alert:triage',
    'alert:escalate',
    'alert:add_note',
    'notes:read_private',
    'mitre:read',
    'incident:read',
    'incident:update',
    'action:propose',
    'audit:read',
    'recommendation:read',
    'recommendation:review',
    'recommendation:validate',
  ],
  security_engineer: [
    'alert:read',
    'mitre:read',
    'mitre:analyze_coverage',
    'incident:read',
    'audit:read',
    'recommendation:create',
    'recommendation:read',
    'recommendation:update',
  ],
  it_operations: [
    'alert:read_scoped_only',
    'incident:read',
    'incident:update',
    'action:authorize_simulated',
    'audit:read',
  ],
  // Super Admin: Platform administration ONLY. Explicitly isolated from private SOC alerts and investigation notes!
  super_admin: [
    'platform:admin',
    'platform:health_read',
    'audit:read',
    'audit:export',
  ],
};

export const ROLE_METADATA: Record<UserRole, { label: string; badge: string; description: string }> = {
  soc_analyst: {
    label: 'SOC Analyst',
    badge: 'Tier 1/2 Triage',
    description: 'Investigate alerts, correlate telemetry with MITRE ATT&CK, record findings, and recommend escalation.',
  },
  security_engineer: {
    label: 'Security Engineer',
    badge: 'Detection Engineering',
    description: 'Analyze threat tactics, evaluate defensive coverage, and inspect detection strategies and mitigations.',
  },
  it_operations: {
    label: 'IT Operations',
    badge: 'Remediation & Recovery',
    description: 'Execute authorized containment tasks, restore affected assets, and track operational recovery.',
  },
  super_admin: {
    label: 'Platform Administrator',
    badge: 'Super Admin Domain',
    description: 'System health, tenant isolation policies, and platform settings. Explicitly isolated from private SOC alerts.',
  },
};

export const DEMO_PERSONAS: Record<UserRole, UserProfile> = {
  soc_analyst: {
    id: 'usr-analyst-01',
    name: 'Alex Mercer',
    email: 'alex.mercer@soc.internal',
    role: 'soc_analyst',
    callsign: 'SPECTER-1',
    title: 'Senior Incident Analyst',
    accountStatus: 'approved',
  },
  security_engineer: {
    id: 'usr-engineer-01',
    name: 'Elena Rostova',
    email: 'elena.rostova@soc.internal',
    role: 'security_engineer',
    callsign: 'SENTINEL-4',
    title: 'Detection Engineer',
    accountStatus: 'approved',
  },
  it_operations: {
    id: 'usr-itops-01',
    name: 'Marcus Vance',
    email: 'marcus.vance@soc.internal',
    role: 'it_operations',
    callsign: 'RECOVERY-9',
    title: 'Lead Systems Administrator',
    accountStatus: 'approved',
  },
  super_admin: {
    id: 'usr-admin-01',
    name: 'Sarah Lin',
    email: 'sarah.lin@platform.internal',
    role: 'super_admin',
    callsign: 'SYSADMIN-0',
    title: 'Platform Security Administrator',
    accountStatus: 'approved',
  },
};

export class AccessDeniedError extends Error {
  public readonly requiredPermission: Permission;
  public readonly userRole: UserRole;

  constructor(message: string, requiredPermission: Permission, userRole: UserRole) {
    super(message);
    this.name = 'AccessDeniedError';
    this.requiredPermission = requiredPermission;
    this.userRole = userRole;
  }
}
