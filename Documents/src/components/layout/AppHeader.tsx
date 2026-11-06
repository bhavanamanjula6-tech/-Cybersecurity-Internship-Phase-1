import React, { useState, useEffect, useRef } from 'react';
import { Shield, Clock, LogOut, User, Globe, ChevronDown, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ROLE_METADATA, ROLE_PERMISSIONS } from '../../types/auth';
import { ThemeToggle } from '../common/ThemeToggle';

interface AppHeaderProps {
  alertCount: number;
  criticalCount: number;
  onExitToPublic: () => void;
  onNavigateToProfile?: () => void;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  alertCount,
  criticalCount,
  onExitToPublic,
  onNavigateToProfile,
}) => {
  const { currentUser, logout } = useAuth();
  const [utcTime, setUtcTime] = useState('');
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Keyboard accessibility and click-outside listener
  useEffect(() => {
    if (!userMenuOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setUserMenuOpen(false);
        buttonRef.current?.focus();
      }
    };

    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [userMenuOpen]);

  const handleSignOut = () => {
    setUserMenuOpen(false);
    logout();
    onExitToPublic();
  };

  const handleOpenProfile = () => {
    setUserMenuOpen(false);
    if (onNavigateToProfile) {
      onNavigateToProfile();
    }
  };

  const roleMeta = currentUser ? ROLE_METADATA[currentUser.role] : null;
  const permissions = currentUser ? (ROLE_PERMISSIONS[currentUser.role] || []) : [];

  return (
    <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-100 sticky top-0 z-40 select-none shadow-xs transition-colors">
      <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3 cursor-pointer" onClick={onExitToPublic}>
          <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-cyan-950 border border-blue-200 dark:border-cyan-500/40 flex items-center justify-center text-blue-600 dark:text-cyan-400 shadow-xs">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-heading font-bold tracking-wider text-sm text-slate-900 dark:text-slate-100">
                KRYPTRION
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-100 dark:bg-cyan-950 text-slate-700 dark:text-cyan-400 border border-slate-200 dark:border-cyan-800 rounded">
                SECURE WORKSPACE
              </span>
            </div>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-none font-sans">
              AI Security Operations Platform
            </p>
          </div>
        </div>

        {/* Center operational counters */}
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
            <Clock className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
            <span className="text-slate-700 dark:text-slate-300 font-medium">{utcTime || '00:00:00 UTC'}</span>
          </div>

          <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400">QUEUE:</span>
            <span className="text-slate-900 dark:text-slate-100 font-bold">{alertCount} Alerts</span>
            {criticalCount > 0 && (
              <span className="text-rose-600 dark:text-rose-400 font-bold bg-rose-50 dark:bg-rose-950/70 px-1.5 rounded border border-rose-200 dark:border-rose-800/80">
                {criticalCount} CRIT
              </span>
            )}
          </div>
        </div>

        {/* Right tools: Theme Toggle, Profile Badge & Sign Out */}
        <div className="flex items-center gap-3">
          <ThemeToggle />

          {currentUser && (
            <div className="relative" ref={menuRef}>
              <button
                ref={buttonRef}
                type="button"
                id="user-menu-button"
                aria-expanded={userMenuOpen}
                aria-haspopup="true"
                aria-label="Account and user settings menu"
                onClick={() => setUserMenuOpen((prev) => !prev)}
                className="flex items-center gap-2 p-1.5 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition cursor-pointer text-left shadow-xs focus:outline-hidden focus:ring-2 focus:ring-blue-500/50"
              >
                <div className="w-7 h-7 rounded-md bg-blue-600 dark:bg-slate-800 text-white dark:text-cyan-400 flex items-center justify-center font-mono text-xs font-bold overflow-hidden shrink-0">
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
                <div className="hidden sm:block text-xs">
                  <div className="font-bold text-slate-900 dark:text-slate-200 leading-tight">
                    {currentUser.name}
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1">
                    <span>{currentUser.callsign}</span>
                    <span>&bull;</span>
                    <span>{roleMeta?.label}</span>
                  </div>
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-150 ${userMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* User Dropdown Menu */}
              {userMenuOpen && (
                <div
                  role="menu"
                  aria-orientation="vertical"
                  aria-labelledby="user-menu-button"
                  className="absolute right-0 mt-2 w-72 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl shadow-xl p-3 z-50 text-xs font-sans space-y-3"
                >
                  {/* Account Header */}
                  <div className="flex items-center gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
                    <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center font-mono text-sm font-bold text-blue-600 dark:text-cyan-400 overflow-hidden shrink-0">
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
                    <div className="min-w-0 flex-1">
                      <div className="font-bold text-slate-900 dark:text-slate-100 truncate">
                        {currentUser.name}
                      </div>
                      <div className="text-[11px] font-mono text-blue-600 dark:text-cyan-400 truncate">
                        {currentUser.callsign} &bull; {currentUser.email}
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate mt-0.5">
                        {currentUser.title}
                      </div>
                    </div>
                  </div>

                  {/* Primary Action: My Profile */}
                  <button
                    type="button"
                    role="menuitem"
                    onClick={handleOpenProfile}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg bg-blue-50/60 dark:bg-slate-800/80 hover:bg-blue-100/70 dark:hover:bg-slate-800 text-blue-700 dark:text-cyan-300 transition text-xs font-medium cursor-pointer border border-blue-200/50 dark:border-slate-700"
                  >
                    <User className="w-4 h-4 shrink-0" />
                    <div className="text-left flex-1">
                      <div className="font-semibold">My Profile</div>
                      <div className="text-[10px] text-blue-600/80 dark:text-slate-400 font-normal">
                        View operational identity & bound credentials
                      </div>
                    </div>
                  </button>

                  {/* Role & Permissions Summary */}
                  <div className="p-2.5 bg-slate-50 dark:bg-slate-950/80 rounded-lg border border-slate-200 dark:border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                        Role & Permissions
                      </span>
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-blue-100 text-blue-700 dark:bg-cyan-950 dark:text-cyan-400 border border-blue-200 dark:border-cyan-800">
                        {roleMeta?.badge}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-600 dark:text-slate-300 font-medium leading-tight">
                      {roleMeta?.label}
                    </p>
                    <p className="text-[10px] text-slate-500 dark:text-slate-400 line-clamp-2">
                      {roleMeta?.description}
                    </p>

                    <div className="pt-1 flex items-center justify-between text-[10px] font-mono border-t border-slate-200/60 dark:border-slate-800/80">
                      <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        {permissions.length} Granted RBAC Rules
                      </span>
                      <button
                        type="button"
                        onClick={handleOpenProfile}
                        className="text-blue-600 dark:text-cyan-400 hover:underline cursor-pointer"
                      >
                        Inspect &rarr;
                      </button>
                    </div>
                  </div>

                  {/* Navigation Actions */}
                  <div className="pt-1 flex flex-col gap-1 border-t border-slate-100 dark:border-slate-800 text-xs font-mono">
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setUserMenuOpen(false);
                        onExitToPublic();
                      }}
                      className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 transition flex items-center gap-2 cursor-pointer"
                    >
                      <Globe className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
                      Return to Public Website
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={handleSignOut}
                      className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/70 text-rose-600 dark:text-rose-300 transition flex items-center gap-2 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
