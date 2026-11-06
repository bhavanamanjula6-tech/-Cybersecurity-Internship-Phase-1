/**
 * Centralized Design Tokens
 * Light-first Enterprise SaaS direction with coordinated dark theme.
 * Inspired by modern modular SaaS product standards.
 */

export const DESIGN_TOKENS = {
  palette: {
    // Light mode surfaces (Default SaaS style)
    light: {
      bgBase: 'bg-slate-50', // #F8FAFC
      bgSurface: 'bg-white', // #FFFFFF
      bgSecondary: 'bg-slate-100', // #F1F5F9
      bgElevated: 'bg-white shadow-sm',
      borderSubtle: 'border-slate-200', // #E2E8F0
      borderProminent: 'border-slate-300',
      textPrimary: 'text-slate-900', // #0F172A
      textSecondary: 'text-slate-600', // #475569
      textMuted: 'text-slate-400',
      primaryAction: 'bg-blue-600 hover:bg-blue-700 text-white', // #2563EB
      secondaryAccent: 'text-cyan-700', // #0891B2
      badgeBackground: 'bg-slate-100 text-slate-700 border-slate-200',
    },
    // Coordinated dark mode (Optional dark mode)
    dark: {
      bgBase: 'dark:bg-slate-950', // #0B0F19
      bgSurface: 'dark:bg-slate-900', // #111827
      bgSecondary: 'dark:bg-slate-800/60', // #1E293B
      bgElevated: 'dark:bg-slate-900 dark:border-slate-800',
      borderSubtle: 'dark:border-slate-800',
      borderProminent: 'dark:border-slate-700',
      textPrimary: 'dark:text-slate-100',
      textSecondary: 'dark:text-slate-400',
      textMuted: 'dark:text-slate-500',
      primaryAction: 'dark:bg-blue-600 dark:hover:bg-blue-500 dark:text-white',
      secondaryAccent: 'dark:text-cyan-400',
      badgeBackground: 'dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
    },
  },
  severity: {
    critical: {
      label: 'Critical',
      code: 'CRIT',
      color: '#DC2626',
      badgeClass: 'bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-900',
      dotClass: 'bg-rose-600',
      textClass: 'text-rose-600 dark:text-rose-400',
    },
    high: {
      label: 'High',
      code: 'HIGH',
      color: '#EA580C',
      badgeClass: 'bg-orange-50 text-orange-700 border border-orange-200 dark:bg-orange-950/70 dark:text-orange-300 dark:border-orange-900',
      dotClass: 'bg-orange-600',
      textClass: 'text-orange-600 dark:text-orange-400',
    },
    medium: {
      label: 'Medium',
      code: 'MED',
      color: '#D97706',
      badgeClass: 'bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-900',
      dotClass: 'bg-amber-600',
      textClass: 'text-amber-600 dark:text-amber-400',
    },
    low: {
      label: 'Low',
      code: 'LOW',
      color: '#0D9488',
      badgeClass: 'bg-teal-50 text-teal-800 border border-teal-200 dark:bg-teal-950/70 dark:text-teal-300 dark:border-teal-900',
      dotClass: 'bg-teal-600',
      textClass: 'text-teal-600 dark:text-teal-400',
    },
    informational: {
      label: 'Informational',
      code: 'INFO',
      color: '#64748B',
      badgeClass: 'bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
      dotClass: 'bg-slate-500',
      textClass: 'text-slate-600 dark:text-slate-400',
    },
  },
  status: {
    new: {
      label: 'New Unassigned',
      badgeClass: 'bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-900',
    },
    in_triage: {
      label: 'In Triage',
      badgeClass: 'bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-900',
    },
    escalated: {
      label: 'Escalated to IR',
      badgeClass: 'bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900',
    },
    resolved: {
      label: 'Resolved',
      badgeClass: 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-900',
    },
    false_positive: {
      label: 'False Positive',
      badgeClass: 'bg-slate-100 text-slate-600 border border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
    },
  },
} as const;
