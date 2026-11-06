import React, { useState, useEffect } from 'react';
import { Shield, Clock, UserCheck } from 'lucide-react';
import { UserRole, ROLE_METADATA } from '../../types/auth';
import { ThemeToggle } from '../common/ThemeToggle';

interface NavbarProps {
  currentRole: UserRole;
  onRoleChange: (role: UserRole) => void;
  alertCount: number;
  criticalCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentRole,
  onRoleChange,
  alertCount,
  criticalCount,
}) => {
  const [utcTime, setUtcTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const roleMeta = ROLE_METADATA[currentRole];

  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 sticky top-0 z-40 select-none">
      <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold tracking-wider text-sm text-slate-100">AI SOC PLATFORM</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded">v2.0-MVP</span>
            </div>
            <p className="text-[10px] text-slate-400 leading-none">Security Operations & Incident Response</p>
          </div>
        </div>

        {/* Center operational counters */}
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-950 rounded border border-slate-800">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300">{utcTime || '00:00:00 UTC'}</span>
          </div>

          <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400">QUEUE:</span>
            <span className="text-slate-100 font-bold">{alertCount} Alerts</span>
            {criticalCount > 0 && (
              <span className="text-rose-400 font-bold bg-rose-950/70 px-1 rounded border border-rose-800/80">
                {criticalCount} CRIT
              </span>
            )}
          </div>
        </div>

        {/* Right tools & Role Switcher */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Operational Role Switcher */}
          <div className="flex items-center gap-1.5 bg-slate-950/90 p-1 rounded-md border border-slate-800">
            <UserCheck className="w-3.5 h-3.5 text-slate-400 ml-1.5 hidden sm:block" />
            <span className="text-[11px] font-mono text-slate-400 hidden md:inline">ROLE:</span>
            <select
              value={currentRole}
              onChange={(e) => onRoleChange(e.target.value as UserRole)}
              className="bg-slate-900 text-xs font-mono font-medium text-slate-200 border border-slate-700 rounded px-2 py-1 focus:ring-1 focus:ring-cyan-400 focus:outline-none cursor-pointer"
              aria-label="Switch operational perspective"
            >
              <option value="soc_analyst">SOC Analyst ({ROLE_METADATA.soc_analyst.badge})</option>
              <option value="security_engineer">Security Engineer ({ROLE_METADATA.security_engineer.badge})</option>
              <option value="it_operations">IT Operations ({ROLE_METADATA.it_operations.badge})</option>
            </select>
          </div>

          {/* Theme Toggle */}
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
};
