import React from 'react';
import {
  AlertOctagon,
  Shield,
  ClipboardList,
  FileText,
  Activity,
  Layers,
  Info,
} from 'lucide-react';
import { UserRole, ROLE_METADATA } from '../../types/auth';

export type NavView = 'alerts' | 'mitre' | 'tasks' | 'audit';

interface SidebarProps {
  currentView: NavView;
  onViewChange: (view: NavView) => void;
  currentRole: UserRole;
  alertCount: number;
  taskCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onViewChange,
  currentRole,
  alertCount,
  taskCount,
}) => {
  const roleMeta = ROLE_METADATA[currentRole];

  const navItems: Array<{
    id: NavView;
    label: string;
    description: string;
    icon: React.ReactNode;
    badgeCount?: number;
    recommendedFor?: UserRole;
  }> = [
    {
      id: 'alerts',
      label: 'Alert Triage Queue',
      description: 'Incoming alerts, telemetry, and deterministic evaluation',
      icon: <AlertOctagon className="w-4 h-4 text-rose-400" />,
      badgeCount: alertCount,
      recommendedFor: 'soc_analyst',
    },
    {
      id: 'mitre',
      label: 'MITRE ATT&CK Matrix',
      description: 'Enterprise tactics, techniques, and defensive coverage',
      icon: <Layers className="w-4 h-4 text-cyan-400" />,
      recommendedFor: 'security_engineer',
    },
    {
      id: 'tasks',
      label: 'Incident Response Tasks',
      description: 'Authorized containment procedures and host recovery',
      icon: <ClipboardList className="w-4 h-4 text-amber-400" />,
      badgeCount: taskCount,
      recommendedFor: 'it_operations',
    },
    {
      id: 'audit',
      label: 'Action Audit Trail',
      description: 'Tamper-evident log of simulated containment actions',
      icon: <FileText className="w-4 h-4 text-slate-400" />,
    },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 select-none">
      {/* Current role context box */}
      <div className="p-3 border-b border-slate-800 bg-slate-950/40">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">ACTIVE PROFILE</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80">
            {roleMeta.badge}
          </span>
        </div>
        <p className="text-xs font-semibold text-slate-100 mt-1">{roleMeta.label}</p>
        <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">{roleMeta.description}</p>
      </div>

      {/* Navigation items */}
      <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
        <div className="px-2 py-1 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
          OPERATIONAL WORKSPACES
        </div>
        {navItems.map((item) => {
          const isActive = currentView === item.id;
          const isRecommended = item.recommendedFor === currentRole;

          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-left transition-all text-xs font-medium ${
                isActive
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-xs'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <span className="shrink-0">{item.icon}</span>
                <div className="truncate">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate">{item.label}</span>
                    {isRecommended && (
                      <span className="shrink-0 text-[9px] font-mono px-1 py-0.2 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                        PRIMARY
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {typeof item.badgeCount === 'number' && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    isActive ? 'bg-cyan-950 text-cyan-300' : 'bg-slate-800 text-slate-400'
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
      <div className="p-3 border-t border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 space-y-1">
        <div className="flex items-center gap-1.5 text-slate-300 font-semibold text-[10px] font-mono uppercase">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          DATA PROVENANCE (PROTOTYPE)
        </div>
        <p className="text-[10px] text-slate-400">
          • MITRE ATT&CK: <span className="text-slate-300">Curated v14.1 Subset</span><br />
          • Network Flow: <span className="text-slate-300">Synthetic CIC-IDS2017</span><br />
          • Security Alerts: <span className="text-purple-400">Synthetic Scenarios</span>
        </p>
      </div>
    </aside>
  );
};
