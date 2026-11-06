import React from 'react';
import {
  AlertOctagon,
  Layers,
  ClipboardList,
  FileText,
  Activity,
  Shield,
  Server,
  LayoutDashboard,
  Search,
  BookOpen,
  FileCode,
  TrendingUp,
  Database,
  ShieldCheck,
} from 'lucide-react';
import { UserRole, ROLE_METADATA, UserProfile } from '../../types/auth';
import { getRepositories } from '../../repositories';

export type WorkspaceView =
  | 'overview'
  | 'strategies'
  | 'analytics'
  | 'log_sources'
  | 'data_components'
  | 'mitre_explorer'
  | 'itops_overview'
  | 'itops_techniques'
  | 'itops_mitigations'
  | 'seceng_overview'
  | 'alerts'
  | 'investigations'
  | 'playbooks'
  | 'mitre'
  | 'tasks'
  | 'audit'
  | 'profile'
  | 'admin';

interface AppSidebarProps {
  currentView: WorkspaceView;
  onViewChange: (view: WorkspaceView) => void;
  currentUser: UserProfile;
  alertCount: number;
  taskCount: number;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  currentView,
  onViewChange,
  currentUser,
  alertCount,
  taskCount,
}) => {
  const roleMeta = ROLE_METADATA[currentUser.role];

  // Role-specific view configurations and permissions
  const allNavItems: Array<{
    id: WorkspaceView;
    label: string;
    description: string;
    icon: React.ReactNode;
    badgeCount?: number;
    authorizedRoles: UserRole[];
    primaryRole?: UserRole;
  }> = [
    {
      id: 'admin',
      label: 'Platform Administration',
      description: 'Domain C governance & isolation policies',
      icon: <Server className="w-4 h-4 text-purple-600 dark:text-purple-400" />,
      authorizedRoles: ['super_admin'],
      primaryRole: 'super_admin',
    },
    // SOC Analyst Six Independent Knowledge Modules
    {
      id: 'overview',
      label: 'SOC Analytics Overview',
      description: 'Cross-dimensional telemetry & knowledge posture',
      icon: <LayoutDashboard className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    {
      id: 'strategies',
      label: 'Detection Strategy Analytics',
      description: 'Technique coverage & strategy blueprints',
      icon: <FileCode className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    {
      id: 'analytics',
      label: 'Analytic Analytics',
      description: 'SIEM & EDR detection rules and coverage',
      icon: <TrendingUp className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    {
      id: 'log_sources',
      label: 'Log Source Analytics',
      description: 'Telemetry data feeds & technique mappings',
      icon: <Server className="w-4 h-4 text-amber-600 dark:text-amber-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    {
      id: 'data_components',
      label: 'Data Component Analytics',
      description: 'Observable telemetry elements & data context',
      icon: <Database className="w-4 h-4 text-purple-600 dark:text-purple-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    {
      id: 'mitre_explorer',
      label: 'MITRE ATT&CK Explorer',
      description: 'Enterprise tactics, techniques & defenses',
      icon: <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-cyan-400" />,
      authorizedRoles: ['soc_analyst'],
      primaryRole: 'soc_analyst',
    },
    // IT Operations Three Dedicated Knowledge Modules
    {
      id: 'itops_overview',
      label: 'IT Operations Overview',
      description: 'Computing platform coverage & defensive posture',
      icon: <LayoutDashboard className="w-4 h-4 text-amber-600 dark:text-amber-400" />,
      authorizedRoles: ['it_operations'],
      primaryRole: 'it_operations',
    },
    {
      id: 'itops_techniques',
      label: 'Technique & Platform Explorer',
      description: 'Techniques categorized by computing environment',
      icon: <Server className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />,
      authorizedRoles: ['it_operations'],
      primaryRole: 'it_operations',
    },
    {
      id: 'itops_mitigations',
      label: 'Mitigation Explorer',
      description: 'Preventative mitigations & protected techniques',
      icon: <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />,
      authorizedRoles: ['it_operations'],
      primaryRole: 'it_operations',
    },
    // Security Engineer Dedicated Modules
    {
      id: 'seceng_overview',
      label: 'Overview',
      description: 'MITRE technique & mitigation reference posture',
      icon: <LayoutDashboard className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />,
      authorizedRoles: ['security_engineer'],
      primaryRole: 'security_engineer',
    },
    {
      id: 'mitre',
      label: 'Threat Intelligence (MITRE ATT&CK)',
      description: 'Enterprise tactics, techniques & defenses',
      icon: <Layers className="w-4 h-4 text-blue-600 dark:text-cyan-400" />,
      authorizedRoles: ['security_engineer'],
      primaryRole: 'security_engineer',
    },
    // Operational Roles Navigation Modules
    {
      id: 'tasks',
      label: 'Incident Response Tasks',
      description: 'Authorized containment & recovery tasks',
      icon: <ClipboardList className="w-4 h-4 text-amber-600 dark:text-amber-400" />,
      badgeCount: taskCount,
      authorizedRoles: ['it_operations'],
      primaryRole: 'it_operations',
    },
    {
      id: 'alerts',
      label: currentUser.role === 'it_operations' ? 'Scoped Incident Alerts' : 'Alert Triage Queue',
      description: 'Incoming alerts & telemetry evidence',
      icon: <AlertOctagon className="w-4 h-4 text-rose-600 dark:text-rose-400" />,
      badgeCount: alertCount,
      authorizedRoles: ['soc_analyst', 'security_engineer', 'it_operations'],
    },
    {
      id: 'investigations',
      label: 'Deep Investigation',
      description: 'Forensic evidence & note correlation',
      icon: <Search className="w-4 h-4 text-sky-600 dark:text-sky-400" />,
      authorizedRoles: ['soc_analyst'],
    },
    {
      id: 'playbooks',
      label: 'Response Playbooks',
      description: 'Containment simulation SOPs',
      icon: <BookOpen className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />,
      authorizedRoles: ['soc_analyst'],
    },
    {
      id: 'audit',
      label: 'Containment Audit Trail',
      description: 'Tamper-evident log of response actions',
      icon: <FileText className="w-4 h-4 text-purple-600 dark:text-purple-400" />,
      authorizedRoles: ['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'],
    },
  ];

  // Filter items visible to current role
  const visibleNavItems = allNavItems.filter((item) =>
    item.authorizedRoles.includes(currentUser.role)
  );

  return (
    <aside className="w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col shrink-0 select-none transition-colors">
      {/* Current role context box */}
      <div className="p-3.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold">
            AUTHORIZED WORKSPACE
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-blue-50 text-blue-700 border border-blue-200 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-800/80">
            {roleMeta.badge}
          </span>
        </div>
        <p className="text-xs font-bold text-slate-900 dark:text-slate-100 mt-1 font-heading">{roleMeta.label}</p>
        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-2 font-sans">{roleMeta.description}</p>
      </div>

      {/* Navigation items */}
      <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
        <div className="px-2 py-1 text-[10px] font-mono text-slate-400 uppercase tracking-wider font-bold">
          ROLE MODULES
        </div>
        {visibleNavItems.map((item) => {
          const isActive = currentView === item.id;
          const isPrimary = item.primaryRole === currentUser.role;

          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-left transition-all text-xs font-medium cursor-pointer ${
                isActive
                  ? 'bg-blue-50 dark:bg-slate-800 text-blue-700 dark:text-cyan-300 border border-blue-200 dark:border-slate-700 font-semibold shadow-xs'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <span className="shrink-0">{item.icon}</span>
                <div className="truncate">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate">{item.label}</span>
                    {isPrimary && (
                      <span className="shrink-0 text-[9px] font-mono px-1 py-0.2 rounded bg-blue-100 dark:bg-cyan-950/80 text-blue-700 dark:text-cyan-400 border border-blue-200 dark:border-cyan-800/60">
                        PRIMARY
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {typeof item.badgeCount === 'number' && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    isActive
                      ? 'bg-blue-100 dark:bg-cyan-950 text-blue-800 dark:text-cyan-300'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  {item.badgeCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Data Provenance summary */}
      {(() => {
        let isLive = false;
        try {
          const repoBundle = getRepositories();
          isLive = repoBundle.mode === 'live_supabase' || repoBundle.isLive;
        } catch {
          isLive = false;
        }

        return (
          <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-[10px] font-mono uppercase">
              {isLive ? (
                <>
                  <Database className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span className="text-emerald-700 dark:text-emerald-300">DATA PROVENANCE: LIVE SUPABASE POSTGRESQL</span>
                </>
              ) : (
                <>
                  <Shield className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                  <span className="text-amber-700 dark:text-amber-300">DATA PROVENANCE: LOCAL DEMO STORE</span>
                </>
              )}
            </div>
            <p className="text-[10px] leading-relaxed">
              &bull; Operational Data: <span className="text-slate-700 dark:text-slate-300 font-mono">{isLive ? 'Live Supabase RLS Store' : 'Local Demo Repository'}</span><br />
              &bull; MITRE ATT&CK: <span className="text-slate-700 dark:text-slate-300 font-mono">Curated v14.1 Taxonomy</span><br />
              &bull; Telemetry: <span className="text-slate-700 dark:text-slate-300 font-mono">Synthetic CIC-IDS2017</span>
            </p>
          </div>
        );
      })()}
    </aside>
  );
};
