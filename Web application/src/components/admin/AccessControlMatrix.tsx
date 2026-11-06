import React from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  MinusCircle,
  Sparkles,
  Lock,
  Layers,
  Activity,
  FileText,
  AlertTriangle,
  Info,
  Server,
  UserCheck,
} from 'lucide-react';
import {
  UserRole,
  Permission,
  ROLE_METADATA,
  ROLE_PERMISSIONS,
} from '../../types/auth';
import {
  AuthorizationService,
} from '../../services/authorizationService';

export interface WorkspaceViewDefinition {
  id: string;
  name: string;
  category: 'Operations' | 'Engineering' | 'Governance' | 'Shared';
  description: string;
}

export const ALL_WORKSPACE_VIEWS: WorkspaceViewDefinition[] = [
  {
    id: 'overview',
    name: 'SOC Overview',
    category: 'Operations',
    description: 'Executive triage metrics, SLA posture, and live incident stream.',
  },
  {
    id: 'alerts',
    name: 'Alert Triage Queue',
    category: 'Operations',
    description: 'Incoming SIEM alerts, detection evidence, and operator assignment.',
  },
  {
    id: 'investigations',
    name: 'Deep Investigation',
    category: 'Operations',
    description: 'Forensic event timelines, correlated telemetry, and private notes.',
  },
  {
    id: 'playbooks',
    name: 'Response Playbooks',
    category: 'Operations',
    description: 'Standard containment procedures and simulated remediation.',
  },
  {
    id: 'mitre',
    name: 'Threat Intel (MITRE)',
    category: 'Engineering',
    description: 'Enterprise tactics, defensive coverage matrix, and rule gaps.',
  },
  {
    id: 'tasks',
    name: 'Incident Response Tasks',
    category: 'Operations',
    description: 'Authorized operational containment tasks and remediation tracking.',
  },
  {
    id: 'audit',
    name: 'Compliance & Audit Trail',
    category: 'Governance',
    description: 'Tamper-evident logs of all operator actions and containment events.',
  },
  {
    id: 'profile',
    name: 'Operator Profile',
    category: 'Shared',
    description: 'Session callsign, credential identity, and personal active assignments.',
  },
  {
    id: 'admin',
    name: 'Platform Administration',
    category: 'Governance',
    description: 'User registration approvals, tenant diagnostics, and isolation policy.',
  },
];

export interface PermissionDefinition {
  id: Permission;
  name: string;
  category:
    | 'Alert Triage & Notes'
    | 'Incident Response'
    | 'Threat Engineering'
    | 'Telemetry'
    | 'Audit & Compliance'
    | 'Platform Administration';
  description: string;
}

export const ALL_PERMISSIONS: PermissionDefinition[] = [
  // Alert Triage & Notes
  {
    id: 'alert:read',
    name: 'Read All Alerts',
    category: 'Alert Triage & Notes',
    description: 'Inspect complete alert queues, telemetry payloads, and metadata.',
  },
  {
    id: 'alert:triage',
    name: 'Triage Alerts',
    category: 'Alert Triage & Notes',
    description: 'Transition alert triage statuses (in_triage, dismissed, resolved).',
  },
  {
    id: 'alert:escalate',
    name: 'Escalate to Incident',
    category: 'Alert Triage & Notes',
    description: 'Escalate verified critical alerts into formal security incidents.',
  },
  {
    id: 'alert:add_note',
    name: 'Add Investigation Notes',
    category: 'Alert Triage & Notes',
    description: 'Attach analyst findings and operational commentary to alert records.',
  },
  {
    id: 'alert:read_scoped_only',
    name: 'Read Assigned Alerts Only',
    category: 'Alert Triage & Notes',
    description: 'Restricted view limited strictly to alerts tied to assigned tasks.',
  },
  {
    id: 'notes:read_private',
    name: 'Read Private Notes',
    category: 'Alert Triage & Notes',
    description: 'Access sensitive internal investigation notes and hypotheses.',
  },

  // Incident Response
  {
    id: 'incident:read',
    name: 'Read Incident Records',
    category: 'Incident Response',
    description: 'Review declared incidents, severity classifications, and timelines.',
  },
  {
    id: 'incident:update',
    name: 'Update Incident Status',
    category: 'Incident Response',
    description: 'Modify incident containment status, assignment, and recovery notes.',
  },
  {
    id: 'action:propose',
    name: 'Propose Containment Action',
    category: 'Incident Response',
    description: 'Draft and submit firewall block, isolation, or password reset actions.',
  },
  {
    id: 'action:authorize_simulated',
    name: 'Authorize Simulated Actions',
    category: 'Incident Response',
    description: 'Approve and execute simulated infrastructure remediation actions.',
  },

  // Threat Engineering
  {
    id: 'mitre:read',
    name: 'Read MITRE Matrix',
    category: 'Threat Engineering',
    description: 'Browse authentic ATT&CK enterprise tactics, techniques, and mitigations.',
  },
  {
    id: 'mitre:analyze_coverage',
    name: 'Analyze Defensive Coverage',
    category: 'Threat Engineering',
    description: 'Evaluate detection rule posture and compute ATT&CK coverage gaps.',
  },

  // Audit & Compliance
  {
    id: 'audit:read',
    name: 'Read Audit Logs',
    category: 'Audit & Compliance',
    description: 'Inspect cryptographic tamper-evident containment and operator logs.',
  },
  {
    id: 'audit:export',
    name: 'Export Compliance Logs',
    category: 'Audit & Compliance',
    description: 'Export audit trails as verified JSON/CSV records for external review.',
  },

  // Platform Administration
  {
    id: 'platform:admin',
    name: 'Platform Administration',
    category: 'Platform Administration',
    description: 'Approve or reject operator registrations and manage role assignments.',
  },
  {
    id: 'platform:health_read',
    name: 'Read Platform Health',
    category: 'Platform Administration',
    description: 'View tenant diagnostics, build environment parameters, and telemetry status.',
  },
];

const ROLES_ORDER: UserRole[] = [
  'soc_analyst',
  'security_engineer',
  'it_operations',
  'super_admin',
];

export const AccessControlMatrix: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Policy and Architecture Disclaimer Banner */}
      <div className="p-4 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-purple-50 dark:bg-purple-950/70 border border-purple-200 dark:border-purple-800/80 rounded-lg text-purple-700 dark:text-purple-300 shrink-0 mt-0.5">
            <Lock className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading flex items-center gap-2">
              Authoritative Role-Based Access Control (RBAC) Policy
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-300 dark:border-purple-800 rounded">
                READ-ONLY POLICY ENFORCEMENT
              </span>
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              This matrix displays the canonical access boundaries defined in{' '}
              <code className="px-1 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-200">
                src/services/authorizationService.ts
              </code>{' '}
              and{' '}
              <code className="px-1 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-200">
                src/types/auth.ts
              </code>
              . These definitions govern both high-level workspace view routing and fine-grained operational action authorization.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
          <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
            <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 mb-1">
              <ShieldCheck className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              Dual-Layer Enforcement
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              In browser memory, <code className="font-mono">AuthorizationService</code> gates views and actions. In production, matching PostgreSQL Row-Level Security (RLS) policies enforce least privilege at the database layer.
            </p>
          </div>

          <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
            <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              Super Admin Segregation
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Platform Administrators have zero access to live SOC alerts, private notes, or operational containment tasks. Super Admin is strictly isolated to tenant diagnostics and account governance.
            </p>
          </div>

          <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
            <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 mb-1">
              <Info className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
              Static Code Derivation
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Values in this matrix are derived live from authoritative code maps rather than a disconnected copy. Any modification requires an audited code release.
            </p>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* PART 1: WORKSPACE VIEW ACCESS MATRIX */}
      {/* ========================================================================= */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-600 dark:text-purple-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
                Workspace View Authorization
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                10 VIEWS
              </span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Evaluates UI navigation access for each role based on <code className="font-mono">ROLE_AUTHORIZED_VIEWS</code> and identifies primary landing views (<code className="font-mono">ROLE_DEFAULT_VIEW</code>).
            </p>
          </div>

          {/* Quick Legend */}
          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-600 dark:text-slate-400 self-start sm:self-auto">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              Authorized
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-purple-500"></span>
              Default Landing
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-700"></span>
              Denied
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse" role="table" aria-label="Workspace View Access Matrix">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/70 border-b border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-600 dark:text-slate-400 uppercase">
                <th scope="col" className="py-3 px-4 font-semibold min-w-[220px]">
                  Workspace View
                </th>
                <th scope="col" className="py-3 px-3 font-semibold min-w-[110px]">
                  Category
                </th>
                {ROLES_ORDER.map((role) => (
                  <th scope="col" key={role} className="py-3 px-3 font-semibold text-center min-w-[140px]">
                    <div className="flex flex-col items-center">
                      <span className="text-slate-900 dark:text-slate-100 font-bold">
                        {ROLE_METADATA[role].label}
                      </span>
                      <span className="text-[9px] font-normal text-slate-500">
                        ({AuthorizationService.ROLE_AUTHORIZED_VIEWS[role].length} views)
                      </span>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-xs">
              {ALL_WORKSPACE_VIEWS.map((view) => (
                <tr
                  key={view.id}
                  className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30 transition-colors"
                >
                  <th scope="row" className="py-3 px-4 font-normal">
                    <div className="font-semibold text-slate-900 dark:text-slate-100">
                      {view.name}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {view.description}
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">
                      id: <code className="text-purple-600 dark:text-purple-400">{view.id}</code>
                    </div>
                  </th>
                  <td className="py-3 px-3">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                        view.category === 'Operations'
                          ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/80 dark:text-blue-300'
                          : view.category === 'Engineering'
                          ? 'bg-cyan-50 text-cyan-700 dark:bg-cyan-950/80 dark:text-cyan-300'
                          : view.category === 'Governance'
                          ? 'bg-purple-50 text-purple-700 dark:bg-purple-950/80 dark:text-purple-300'
                          : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                      }`}
                    >
                      {view.category}
                    </span>
                  </td>
                  {ROLES_ORDER.map((role) => {
                    const isAuthorized = AuthorizationService.isViewAuthorized(role, view.id);
                    const isDefaultLanding = AuthorizationService.ROLE_DEFAULT_VIEW[role] === view.id;

                    return (
                      <td key={role} className="py-3 px-3 text-center align-middle">
                        {isAuthorized ? (
                          <div className="flex flex-col items-center justify-center gap-1">
                            {isDefaultLanding ? (
                              <span
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-300 dark:border-purple-800 shadow-xs"
                                title={`Default landing view for ${ROLE_METADATA[role].label}`}
                              >
                                <Sparkles className="w-3 h-3 text-purple-600 dark:text-purple-400" />
                                <span>Default Landing</span>
                              </span>
                            ) : (
                              <span
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-50 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/80"
                                title={`Authorized for ${ROLE_METADATA[role].label}`}
                              >
                                <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                                <span>Authorized</span>
                              </span>
                            )}
                          </div>
                        ) : (
                          <div className="flex items-center justify-center">
                            <span
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 dark:text-slate-600"
                              title={`Denied for ${ROLE_METADATA[role].label}`}
                            >
                              <MinusCircle className="w-3 h-3 text-slate-300 dark:text-slate-700" />
                              <span>Denied</span>
                            </span>
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* PART 2: GRANULAR ACTION PERMISSIONS MATRIX */}
      {/* ========================================================================= */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-purple-600 dark:text-purple-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
                Granular Action & Capability Permissions
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                17 PERMISSIONS
              </span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Evaluates fine-grained functional capabilities enforced by <code className="font-mono">AuthorizationService.hasPermission</code> and PostgreSQL RLS.
            </p>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-600 dark:text-slate-400 self-start sm:self-auto">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              Granted
            </span>
            <span className="flex items-center gap-1">
              <MinusCircle className="w-3.5 h-3.5 text-slate-300 dark:text-slate-700" />
              Not Granted
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse" role="table" aria-label="Granular Permissions Matrix">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/70 border-b border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-600 dark:text-slate-400 uppercase">
                <th scope="col" className="py-3 px-4 font-semibold min-w-[240px]">
                  Permission & Scope
                </th>
                <th scope="col" className="py-3 px-3 font-semibold min-w-[150px]">
                  Domain
                </th>
                {ROLES_ORDER.map((role) => (
                  <th scope="col" key={role} className="py-3 px-3 font-semibold text-center min-w-[140px]">
                    <div className="flex flex-col items-center">
                      <span className="text-slate-900 dark:text-slate-100 font-bold">
                        {ROLE_METADATA[role].label}
                      </span>
                      <span className="text-[9px] font-normal text-slate-500">
                        ({ROLE_PERMISSIONS[role].length} capabilities)
                      </span>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-xs">
              {ALL_PERMISSIONS.map((perm) => (
                <tr
                  key={perm.id}
                  className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30 transition-colors"
                >
                  <th scope="row" className="py-3 px-4 font-normal">
                    <div className="font-semibold text-slate-900 dark:text-slate-100">
                      {perm.name}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {perm.description}
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">
                      perm: <code className="text-indigo-600 dark:text-indigo-400">{perm.id}</code>
                    </div>
                  </th>
                  <td className="py-3 px-3">
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                      {perm.category}
                    </span>
                  </td>
                  {ROLES_ORDER.map((role) => {
                    const hasPerm = AuthorizationService.hasPermission(role, perm.id);

                    return (
                      <td key={role} className="py-3 px-3 text-center align-middle">
                        {hasPerm ? (
                          <div className="flex items-center justify-center">
                            <span
                              className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-50 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/80"
                              title={`${perm.id} is GRANTED to ${ROLE_METADATA[role].label}`}
                            >
                              <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                              <span>Granted</span>
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center justify-center">
                            <span
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 dark:text-slate-600"
                              title={`${perm.id} is NOT GRANTED to ${ROLE_METADATA[role].label}`}
                            >
                              <MinusCircle className="w-3 h-3 text-slate-300 dark:text-slate-700" />
                              <span>Not Granted</span>
                            </span>
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* PART 3: ARCHITECTURAL ROLE BOUNDARY SUMMARY */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {ROLES_ORDER.map((role) => {
          const meta = ROLE_METADATA[role];
          const viewCount = AuthorizationService.ROLE_AUTHORIZED_VIEWS[role].length;
          const permCount = ROLE_PERMISSIONS[role].length;
          const defaultViewId = AuthorizationService.ROLE_DEFAULT_VIEW[role];
          const defaultViewObj = ALL_WORKSPACE_VIEWS.find((v) => v.id === defaultViewId);

          return (
            <div
              key={role}
              className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-2 shadow-xs"
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                  {meta.badge}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  {role}
                </span>
              </div>

              <div className="text-sm font-bold text-slate-900 dark:text-slate-100">
                {meta.label}
              </div>

              <p className="text-[11px] text-slate-500 dark:text-slate-400 min-h-[36px]">
                {meta.description}
              </p>

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80 space-y-1 text-xs font-mono">
                <div className="flex justify-between text-slate-600 dark:text-slate-400">
                  <span>Views Authorized:</span>
                  <span className="font-bold text-slate-900 dark:text-slate-100">{viewCount} / 10</span>
                </div>
                <div className="flex justify-between text-slate-600 dark:text-slate-400">
                  <span>Capabilities:</span>
                  <span className="font-bold text-slate-900 dark:text-slate-100">{permCount} / 17</span>
                </div>
                <div className="flex justify-between text-slate-600 dark:text-slate-400">
                  <span>Default Landing:</span>
                  <span className="font-bold text-purple-600 dark:text-purple-400">{defaultViewObj?.name || defaultViewId}</span>
                </div>
              </div>

              {role === 'super_admin' && (
                <div className="mt-2 p-2 rounded bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-900/60 text-[10px] text-amber-800 dark:text-amber-300 flex items-start gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                  <span>
                    <strong>Segregation of Duties:</strong> Strictly isolated from live alerts, investigations, and private notes.
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
