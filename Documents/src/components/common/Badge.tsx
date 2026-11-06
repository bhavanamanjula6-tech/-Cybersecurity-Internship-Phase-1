import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'info' | 'success' | 'warning' | 'danger' | 'purple' | 'cyan';
  size?: 'xs' | 'sm' | 'md';
  className?: string;
  title?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'sm',
  className = '',
  title,
}) => {
  const sizeClasses = {
    xs: 'px-1.5 py-0.5 text-[10px] font-mono leading-tight tracking-wider',
    sm: 'px-2 py-0.5 text-xs font-mono font-medium',
    md: 'px-2.5 py-1 text-xs font-semibold',
  };

  const variantClasses = {
    default: 'bg-slate-800 text-slate-300 border border-slate-700 dark:bg-slate-800 dark:text-slate-300',
    info: 'bg-sky-500/10 text-sky-400 border border-sky-500/30 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800',
    success: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800',
    warning: 'bg-amber-500/10 text-amber-400 border border-amber-500/30 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800',
    danger: 'bg-rose-500/10 text-rose-400 border border-rose-500/30 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800',
    purple: 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 dark:bg-indigo-950/60 dark:text-indigo-300 dark:border-indigo-800',
    cyan: 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 dark:bg-cyan-950/60 dark:text-cyan-300 dark:border-cyan-800',
  };

  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded font-mono uppercase tracking-wide select-none ${sizeClasses[size]} ${variantClasses[variant]} ${className}`}
    >
      {children}
    </span>
  );
};
