import React from 'react';
import { UserProfile, ROLE_METADATA, ROLE_PERMISSIONS } from '../../types/auth';
import { ProvenanceBadge } from './ProvenanceBadge';
import { Button } from './Button';
import {
  User,
  Shield,
  CheckCircle2,
  LogOut,
  Mail,
} from 'lucide-react';

interface UserProfilePageProps {
  currentUser: UserProfile;
  onLogout: () => Promise<void>;
}

export const UserProfilePage: React.FC<UserProfilePageProps> = ({
  currentUser,
  onLogout,
}) => {
  const roleMeta = ROLE_METADATA[currentUser.role];
  const permissions = ROLE_PERMISSIONS[currentUser.role] || [];

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <User className="w-5 h-5 text-slate-400" />
            Operator Profile & Identity
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Active identity, operational callsign, assigned role tier, and authorization boundaries.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={onLogout}
          className="text-xs flex items-center gap-1.5 text-rose-400 border-rose-900/50 hover:bg-rose-950/40 cursor-pointer"
        >
          <LogOut className="w-3.5 h-3.5" />
          Terminate Session / Sign Out
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <ProvenanceBadge
          type="synthetic_demo"
          label="AUTHENTICATED LOCAL CONTEXT"
        />
        <span className="text-xs text-slate-400">
          Profile records are managed through the central AuthContext. No password mutations or role elevation controls are permitted from this view.
        </span>
      </div>

      {/* Profile Overview Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-full bg-slate-800 border-2 border-indigo-500/50 flex items-center justify-center text-lg font-bold text-indigo-300 font-mono overflow-hidden shrink-0">
              {currentUser.avatarUrl ? (
                <img
                  src={currentUser.avatarUrl}
                  alt={currentUser.name}
                  className="w-full h-full object-cover"
                />
              ) : (
                currentUser.callsign ? currentUser.callsign.slice(0, 2) : 'OP'
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-100">{currentUser.name}</h2>
                <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {currentUser.callsign}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{currentUser.title}</p>
              <p className="text-xs text-slate-500 flex items-center gap-1 mt-0.5">
                <Mail className="w-3 h-3" />
                {currentUser.email}
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:items-end gap-1">
            <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/60 px-2.5 py-1 rounded border border-emerald-800">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Status: <span className="font-semibold uppercase">{currentUser.accountStatus || 'approved'}</span>
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              User ID: {currentUser.id}
            </span>
          </div>
        </div>

        {/* Detailed Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-xs pt-4 border-t border-slate-800">
          <div className="p-3 bg-slate-950/60 rounded border border-slate-800 space-y-1">
            <span className="text-[11px] text-slate-500 block">Operational Role</span>
            <span className="font-semibold text-slate-200 block">{roleMeta?.label || currentUser.role}</span>
            <span className="text-[10px] text-slate-400 block">{roleMeta?.badge}</span>
          </div>

          <div className="p-3 bg-slate-950/60 rounded border border-slate-800 space-y-1">
            <span className="text-[11px] text-slate-500 block">Governance Approval</span>
            <span className="font-semibold text-slate-200 block">
              {currentUser.approvedBy ? `Approved by ${currentUser.approvedBy}` : 'Pre-approved System Persona'}
            </span>
            <span className="text-[10px] text-slate-400 block font-mono">
              {currentUser.approvedAt ? new Date(currentUser.approvedAt).toLocaleDateString() : 'Baseline'}
            </span>
          </div>

          <div className="p-3 bg-slate-950/60 rounded border border-slate-800 space-y-1">
            <span className="text-[11px] text-slate-500 block">Audit Binding</span>
            <span className="font-mono text-slate-300 block truncate">
              {currentUser.lastAuditId || 'AUD-BOOTSTRAP-INITIAL'}
            </span>
            <span className="text-[10px] text-slate-400 block">Bound Governance Record</span>
          </div>
        </div>

        {/* Operational Permissions List */}
        <div className="space-y-3 pt-4 border-t border-slate-800">
          <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            Granted Role Capabilities (Least Privilege RBAC)
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
            {permissions.map((perm) => (
              <div
                key={perm}
                className="p-2 bg-slate-950/40 rounded border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-2"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />
                <span className="truncate">{perm}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
