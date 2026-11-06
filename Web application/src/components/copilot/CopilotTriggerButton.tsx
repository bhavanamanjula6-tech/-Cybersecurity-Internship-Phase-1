/**
 * CyberOps SOC — Floating AI Security Copilot Button
 *
 * Positioned fixed at the bottom-right for approved, authenticated operators.
 * Triggers the responsive AI Security Copilot drawer.
 */

import React from 'react';
import { Bot, Sparkles, X } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface CopilotTriggerButtonProps {
  isOpen: boolean;
  onClick: () => void;
  unreadCount?: number;
}

export const CopilotTriggerButton: React.FC<CopilotTriggerButtonProps> = ({
  isOpen,
  onClick,
  unreadCount = 0,
}) => {
  const { currentUser } = useAuth();

  // Strictly render only for approved operators with valid roles
  if (
    !currentUser ||
    currentUser.accountStatus !== 'approved' ||
    !['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'].includes(currentUser.role)
  ) {
    return null;
  }

  return (
    <div className="fixed bottom-6 right-6 z-40 select-none">
      <button
        onClick={onClick}
        type="button"
        aria-label={isOpen ? 'Close AI Security Copilot' : 'Open AI Security Copilot'}
        aria-expanded={isOpen}
        title={isOpen ? 'Close AI Copilot' : 'Open AI Security Copilot (Gemini Advisory)'}
        className={`group relative flex items-center justify-center p-3.5 sm:px-4 sm:py-3 rounded-full shadow-xl transition-all duration-200 cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 dark:focus:ring-offset-slate-900 border ${
          isOpen
            ? 'bg-slate-800 text-white border-slate-700 hover:bg-slate-700'
            : 'bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white border-cyan-400/40 shadow-cyan-900/30 hover:shadow-cyan-500/25'
        }`}
      >
        {/* Pulsing radar ring when closed */}
        {!isOpen && (
          <span className="absolute -inset-0.5 rounded-full bg-cyan-400/30 blur-xs animate-pulse group-hover:opacity-75 transition" />
        )}

        <div className="relative flex items-center gap-2">
          {isOpen ? (
            <X className="w-5 h-5 text-slate-200" />
          ) : (
            <div className="flex items-center gap-2">
              <div className="relative">
                <Bot className="w-5 h-5 text-cyan-100" />
                <span className="absolute -top-1 -right-1 flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-300 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
                </span>
              </div>
              <span className="hidden md:inline font-heading font-semibold text-xs tracking-wider uppercase text-white">
                Copilot
              </span>
              <Sparkles className="hidden md:inline w-3.5 h-3.5 text-cyan-200" />
            </div>
          )}

          {unreadCount > 0 && !isOpen && (
            <span className="absolute -top-1.5 -right-1.5 min-w-[18px] h-[18px] px-1 text-[10px] font-mono font-bold bg-amber-500 text-slate-950 rounded-full flex items-center justify-center shadow-xs">
              {unreadCount}
            </span>
          )}
        </div>
      </button>
    </div>
  );
};
