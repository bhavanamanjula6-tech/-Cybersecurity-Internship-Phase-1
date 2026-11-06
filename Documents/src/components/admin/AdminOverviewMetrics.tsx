import React, { useMemo } from 'react';
import {
  Users,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Database,
  RefreshCw,
  Shield,
  Activity,
  UserCheck,
  UserX,
  Lock,
  BarChart3,
  PieChart,
  TrendingUp,
  AlertCircle,
  Calendar,
  Layers,
} from 'lucide-react';
import { UserRole, ROLE_METADATA, AccountStatus } from '../../types/auth';
import { AuditLogEntry } from '../../types/audit';
import { AdminOverviewStats, DatabaseConnectivityStatus } from '../../services/adminMetricsService';

interface AdminOverviewMetricsProps {
  stats: AdminOverviewStats;
  dbStatus: DatabaseConnectivityStatus;
  isCheckingDb: boolean;
  onRefreshDb?: () => void;
  auditLogs?: AuditLogEntry[];
  isLoadingAuditLogs?: boolean;
  auditLogsError?: string | null;
  onRefreshAuditLogs?: () => void;
  className?: string;
}

export const AdminOverviewMetrics: React.FC<AdminOverviewMetricsProps> = ({
  stats,
  dbStatus,
  isCheckingDb,
  onRefreshDb,
  auditLogs = [],
  isLoadingAuditLogs = false,
  auditLogsError = null,
  onRefreshAuditLogs,
  className = '',
}) => {
  // Ordered role configurations for visualization
  const roleConfigs: {
    role: UserRole;
    name: string;
    description: string;
    count: number;
    barColor: string;
    textColor: string;
    bgColor: string;
    borderColor: string;
  }[] = [
    {
      role: 'soc_analyst',
      name: ROLE_METADATA.soc_analyst.label,
      description: 'Threat detection, triage & live investigation',
      count: stats.roleCounts.soc_analyst,
      barColor: 'bg-blue-600 dark:bg-blue-500',
      textColor: 'text-blue-700 dark:text-blue-300',
      bgColor: 'bg-blue-50 dark:bg-blue-950/70',
      borderColor: 'border-blue-200 dark:border-blue-800',
    },
    {
      role: 'security_engineer',
      name: ROLE_METADATA.security_engineer.label,
      description: 'Detection engineering & MITRE ATT&CK mapping',
      count: stats.roleCounts.security_engineer,
      barColor: 'bg-emerald-600 dark:bg-emerald-500',
      textColor: 'text-emerald-700 dark:text-emerald-300',
      bgColor: 'bg-emerald-50 dark:bg-emerald-950/70',
      borderColor: 'border-emerald-200 dark:border-emerald-800',
    },
    {
      role: 'it_operations',
      name: ROLE_METADATA.it_operations.label,
      description: 'Infrastructure management & remediation tasks',
      count: stats.roleCounts.it_operations,
      barColor: 'bg-amber-600 dark:bg-amber-500',
      textColor: 'text-amber-700 dark:text-amber-300',
      bgColor: 'bg-amber-50 dark:bg-amber-950/70',
      borderColor: 'border-amber-200 dark:border-amber-800',
    },
    {
      role: 'super_admin',
      name: ROLE_METADATA.super_admin.label,
      description: 'Platform governance, bootstrap & access control',
      count: stats.roleCounts.super_admin,
      barColor: 'bg-purple-600 dark:bg-purple-500',
      textColor: 'text-purple-700 dark:text-purple-300',
      bgColor: 'bg-purple-50 dark:bg-purple-950/70',
      borderColor: 'border-purple-200 dark:border-purple-800',
    },
  ];

  // Maximum count for normalizing role bar lengths
  const maxRoleCount = useMemo(() => {
    return Math.max(...roleConfigs.map((r) => r.count), 1);
  }, [roleConfigs]);

  // Account status donut segments computation
  const statusSegments = useMemo(() => {
    const total = stats.totalUsers;
    const items: {
      status: AccountStatus;
      label: string;
      count: number;
      color: string;
      hexColor: string;
      badgeClass: string;
    }[] = [
      {
        status: 'approved',
        label: 'Approved (Active)',
        count: stats.approvedCount,
        color: 'text-emerald-600 dark:text-emerald-400',
        hexColor: '#10b981',
        badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800',
      },
      {
        status: 'pending',
        label: 'Pending Governance',
        count: stats.pendingCount,
        color: 'text-amber-600 dark:text-amber-400',
        hexColor: '#f59e0b',
        badgeClass: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800',
      },
      {
        status: 'disabled',
        label: 'Disabled / Suspended',
        count: stats.disabledCount,
        color: 'text-slate-500 dark:text-slate-400',
        hexColor: '#64748b',
        badgeClass: 'bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
      },
      {
        status: 'rejected',
        label: 'Rejected',
        count: stats.rejectedCount,
        color: 'text-rose-600 dark:text-rose-400',
        hexColor: '#f43f5e',
        badgeClass: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800',
      },
    ];

    const circumference = 2 * Math.PI * 36; // r=36 -> ~226.195
    let cumulative = 0;

    const segments = items.map((item) => {
      const percentage = total > 0 ? (item.count / total) * 100 : 0;
      const strokeLength = total > 0 ? (item.count / total) * circumference : 0;
      const strokeDashoffset = -cumulative;
      if (total > 0) {
        cumulative += strokeLength;
      }
      return {
        ...item,
        percentage,
        strokeDasharray: `${strokeLength.toFixed(2)} ${(circumference - strokeLength).toFixed(2)}`,
        strokeDashoffset: strokeDashoffset.toFixed(2),
      };
    });

    return { total, circumference, segments };
  }, [stats]);

  // Administrative activity time series computation
  const activityTimeSeries = useMemo(() => {
    const width = 560;
    const height = 150;
    const padLeft = 40;
    const padRight = 20;
    const padTop = 15;
    const padBottom = 25;
    const plotWidth = width - padLeft - padRight;
    const plotHeight = height - padTop - padBottom;
    const defaultScaleY = 2;

    if (!auditLogs || auditLogs.length === 0) {
      return {
        dates: [],
        points: [],
        linePath: '',
        areaPath: '',
        maxCount: 0,
        scaleY: defaultScaleY,
        totalEvents: 0,
        width,
        height,
        padLeft,
        padRight,
        padTop,
        padBottom,
        plotWidth,
        plotHeight,
      };
    }

    const countsByDate = new Map<string, number>();
    for (const entry of auditLogs) {
      const dateStr = entry.timestamp ? entry.timestamp.slice(0, 10) : 'Unknown';
      countsByDate.set(dateStr, (countsByDate.get(dateStr) || 0) + 1);
    }

    const sortedDates = Array.from(countsByDate.keys()).sort();
    let maxCount = 0;
    for (const d of sortedDates) {
      const c = countsByDate.get(d) || 0;
      if (c > maxCount) maxCount = c;
    }

    const scaleY = Math.max(maxCount, defaultScaleY);

    const points = sortedDates.map((date, idx) => {
      const count = countsByDate.get(date) || 0;
      const x =
        sortedDates.length === 1
          ? padLeft + plotWidth / 2
          : padLeft + (idx / (sortedDates.length - 1)) * plotWidth;
      const y = padTop + plotHeight - (count / scaleY) * plotHeight;
      return { date, count, x, y };
    });

    const linePath = points
      .map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
      .join(' ');

    const areaPath =
      points.length > 0
        ? `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} L ${points[0].x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} Z`
        : '';

    return {
      dates: sortedDates,
      points,
      linePath,
      areaPath,
      maxCount,
      scaleY,
      totalEvents: auditLogs.length,
      width,
      height,
      padLeft,
      padRight,
      padTop,
      padBottom,
      plotWidth,
      plotHeight,
    };
  }, [auditLogs]);

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
        <div>
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
            <Activity className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            Admin Overview & Health Metrics
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time identity statistics, governance queue counts, and verified database status.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            PLATFORM-LEVEL &bull; ISOLATED FROM ALERTS
          </span>
        </div>
      </div>

      {/* Top 4 Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Registered Users */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs flex flex-col justify-between">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5 font-bold uppercase tracking-wide">
                <Users className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                Total Registered Users
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
                PROFILES
              </span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {stats.totalUsers}
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Across all 4 security operational & admin roles
            </div>
          </div>

          {/* Role Breakdown Mini Chips */}
          <div className="grid grid-cols-2 gap-1.5 pt-3 mt-3 border-t border-slate-100 dark:border-slate-800/80">
            {roleConfigs.map(({ role, name, count, textColor, bgColor, borderColor }) => (
              <div
                key={role}
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border flex items-center justify-between ${textColor} ${bgColor} ${borderColor}`}
              >
                <span className="truncate pr-1">{name}:</span>
                <span className="font-bold">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Card 2: Pending Governance Approvals */}
        <div
          className={`p-4 border rounded-xl shadow-xs flex flex-col justify-between ${
            stats.pendingCount > 0
              ? 'bg-amber-50/50 dark:bg-amber-950/20 border-amber-300 dark:border-amber-800/80'
              : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800'
          }`}
        >
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5 font-bold uppercase tracking-wide">
                <Clock
                  className={`w-3.5 h-3.5 ${
                    stats.pendingCount > 0
                      ? 'text-amber-600 dark:text-amber-400 animate-pulse'
                      : 'text-emerald-600 dark:text-emerald-400'
                  }`}
                />
                Pending Approvals
              </span>
              {stats.pendingCount > 0 ? (
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200 border border-amber-300 dark:border-amber-700">
                  ACTION REQUIRED
                </span>
              ) : (
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-700">
                  QUEUE CLEAR
                </span>
              )}
            </div>
            <div
              className={`text-2xl font-bold font-mono ${
                stats.pendingCount > 0
                  ? 'text-amber-700 dark:text-amber-300'
                  : 'text-slate-900 dark:text-slate-100'
              }`}
            >
              {stats.pendingCount}
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              {stats.pendingCount === 1
                ? '1 operator awaiting role assignment & approval'
                : `${stats.pendingCount} operators awaiting role assignment & approval`}
            </div>
          </div>

          <div className="pt-3 mt-3 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-slate-600 dark:text-slate-400 flex items-center gap-1">
            <Lock className="w-3 h-3 text-slate-400 shrink-0" />
            <span>Unapproved accounts are locked from SOC data</span>
          </div>
        </div>

        {/* Card 3: Account Status Distribution */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs flex flex-col justify-between">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5 font-bold uppercase tracking-wide">
                <UserCheck className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                Status Distribution
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                AUDIT
              </span>
            </div>
            <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {stats.approvedCount}{' '}
              <span className="text-xs font-normal text-slate-400">Active</span>
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Approved operators currently authorized
            </div>
          </div>

          {/* Status Breakdown Chips */}
          <div className="grid grid-cols-2 gap-1.5 pt-3 mt-3 border-t border-slate-100 dark:border-slate-800/80">
            <div className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-200 bg-emerald-50 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800 flex items-center justify-between">
              <span>Approved:</span>
              <span className="font-bold">{stats.approvedCount}</span>
            </div>
            <div className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-amber-200 bg-amber-50 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800 flex items-center justify-between">
              <span>Pending:</span>
              <span className="font-bold">{stats.pendingCount}</span>
            </div>
            <div className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-200 bg-rose-50 text-rose-800 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800 flex items-center justify-between">
              <span>Rejected:</span>
              <span className="font-bold">{stats.rejectedCount}</span>
            </div>
            <div className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-200 bg-slate-50 text-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700 flex items-center justify-between">
              <span>Disabled:</span>
              <span className="font-bold">{stats.disabledCount}</span>
            </div>
          </div>
        </div>

        {/* Card 4: Database & Repository Status */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs flex flex-col justify-between">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5 font-bold uppercase tracking-wide">
                <Database className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                Database & Repository
              </span>
              {onRefreshDb && (
                <button
                  type="button"
                  onClick={onRefreshDb}
                  disabled={isCheckingDb}
                  className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
                  title="Re-probe database connection"
                  aria-label="Re-probe database connection"
                >
                  <RefreshCw className={`w-3 h-3 ${isCheckingDb ? 'animate-spin' : ''}`} />
                </button>
              )}
            </div>

            {/* Verified Connectivity Badge */}
            <div className="flex items-center gap-1.5 pt-1">
              {isCheckingDb ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
                  <RefreshCw className="w-3 h-3 animate-spin text-slate-500" />
                  PROBING...
                </span>
              ) : dbStatus.isConnected ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                  VERIFIED CONNECTED
                </span>
              ) : dbStatus.isConfigured ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800">
                  <AlertTriangle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
                  CONFIGURED (UNREACHABLE)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
                  <Database className="w-3 h-3 text-amber-600 dark:text-amber-400" />
                  LOCAL PROTOTYPE MODE
                </span>
              )}
            </div>

            <div className="text-[11px] font-mono text-slate-800 dark:text-slate-200 pt-0.5 truncate">
              {dbStatus.mode === 'live_supabase' ? 'Supabase PostgreSQL' : 'Local In-Memory Adapter'}
            </div>
            <div className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight">
              {dbStatus.detail}
            </div>
          </div>

          <div className="pt-2 mt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>Configured: {dbStatus.isConfigured ? 'Yes' : 'No'}</span>
            <span>Probe: {dbStatus.isConnected ? 'Pass' : 'Local/Fail'}</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUPER ADMIN VISUALIZATIONS GRID */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Visualization 1: Users by Role (Horizontal Bar Chart) */}
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                  Users by Role
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Distribution across all 4 operational and administrative domains
                </p>
              </div>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800">
                {stats.totalUsers} Total
              </span>
            </div>

            {/* Role Bars */}
            <div className="space-y-3.5 pt-1">
              {roleConfigs.map((r) => {
                const percentage =
                  stats.totalUsers > 0 ? Math.round((r.count / stats.totalUsers) * 100) : 0;
                const barWidth =
                  maxRoleCount > 0 ? Math.max((r.count / maxRoleCount) * 100, r.count > 0 ? 4 : 0) : 0;

                return (
                  <div key={r.role} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 truncate">
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${r.barColor}`}
                        />
                        <span className="font-semibold text-slate-800 dark:text-slate-200 truncate">
                          {r.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 font-mono text-[11px] shrink-0">
                        <span className="font-bold text-slate-900 dark:text-slate-100">
                          {r.count}
                        </span>
                        <span className="text-slate-400 text-[10px]">({percentage}%)</span>
                      </div>
                    </div>

                    {/* Progress Bar Container */}
                    <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-2.5 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${r.barColor}`}
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>

                    <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate">
                      {r.description}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-3 mt-4 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-between">
            <span>Authoritative Source: public.user_profiles</span>
            <span>RLS Enforced</span>
          </div>
        </div>

        {/* Visualization 2: User Account Status (SVG Donut Chart) */}
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <PieChart className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                  User Account Status
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Lifecycle distribution across active, pending, disabled, and rejected
                </p>
              </div>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800">
                {stats.approvedCount} Active
              </span>
            </div>

            {/* Donut and Legend Layout */}
            <div className="flex flex-col sm:flex-row items-center justify-around gap-6 pt-2">
              {/* SVG Donut */}
              <div className="relative w-36 h-36 shrink-0 flex items-center justify-center">
                <svg
                  viewBox="0 0 100 100"
                  className="w-full h-full transform -rotate-90"
                  aria-hidden="true"
                >
                  {/* Background track circle */}
                  <circle
                    cx="50"
                    cy="50"
                    r="36"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="14"
                    className="text-slate-100 dark:text-slate-800"
                  />
                  {statusSegments.total > 0 &&
                    statusSegments.segments.map((seg) => {
                      if (seg.count === 0) return null;
                      return (
                        <circle
                          key={seg.status}
                          cx="50"
                          cy="50"
                          r="36"
                          fill="none"
                          stroke={seg.hexColor}
                          strokeWidth="14"
                          strokeDasharray={seg.strokeDasharray}
                          strokeDashoffset={seg.strokeDashoffset}
                          className="transition-all duration-500"
                        />
                      );
                    })}
                </svg>

                {/* Donut Center Display */}
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
                  <span className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
                    {statusSegments.total}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Accounts
                  </span>
                </div>
              </div>

              {/* Status Breakdown Legend */}
              <div className="w-full sm:w-auto space-y-2.5 flex-1 min-w-[180px]">
                {statusSegments.segments.map((seg) => (
                  <div
                    key={seg.status}
                    className={`p-2 rounded-lg border flex items-center justify-between text-xs font-mono ${seg.badgeClass}`}
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ backgroundColor: seg.hexColor }}
                      />
                      <span className="font-semibold text-slate-800 dark:text-slate-200">
                        {seg.label}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 font-bold">
                      <span>{seg.count}</span>
                      <span className="text-[10px] opacity-75 font-normal">
                        ({seg.percentage.toFixed(0)}%)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-3 mt-4 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-between">
            <span>Governance Boundary: Unapproved accounts locked</span>
            <span>Invariant: &Sigma; = {statusSegments.total}</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* Visualization 3: Administrative Activity Over Time (SVG Line Chart) */}
      {/* ========================================================================= */}
      <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800/80 pb-3">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-purple-600 dark:text-purple-400" />
              Administrative Activity Over Time
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Platform governance actions executed and logged into{' '}
              <code className="font-mono text-purple-700 dark:text-purple-300">
                public.audit_logs
              </code>{' '}
              (audit_category = &apos;platform&apos;)
            </p>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto">
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800">
              {activityTimeSeries.totalEvents} Events
            </span>
            {onRefreshAuditLogs && (
              <button
                type="button"
                onClick={onRefreshAuditLogs}
                disabled={isLoadingAuditLogs}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
                title="Refresh platform audit logs"
                aria-label="Refresh platform audit logs"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${isLoadingAuditLogs ? 'animate-spin' : ''}`}
                />
              </button>
            )}
          </div>
        </div>

        {/* Loading State */}
        {isLoadingAuditLogs ? (
          <div className="py-12 flex flex-col items-center justify-center text-center text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin text-purple-600 dark:text-purple-400 mb-2" />
            <div className="text-xs font-mono">Querying platform audit ledger...</div>
          </div>
        ) : auditLogsError ? (
          /* Error State with explicit Retry */
          <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 flex items-center justify-between text-xs text-rose-800 dark:text-rose-200">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
              <span>{auditLogsError}</span>
            </div>
            {onRefreshAuditLogs && (
              <button
                onClick={onRefreshAuditLogs}
                className="px-2.5 py-1 font-mono font-bold text-[11px] bg-rose-600 hover:bg-rose-700 text-white rounded transition"
              >
                Retry
              </button>
            )}
          </div>
        ) : activityTimeSeries.points.length === 0 ? (
          /* Truthful Empty State (Zero Fabricated Points) */
          <div className="py-10 px-4 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-dashed border-slate-200 dark:border-slate-800 flex flex-col items-center justify-center text-center space-y-2">
            <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-900 flex items-center justify-center text-slate-400">
              <Shield className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div className="text-xs font-bold font-mono text-slate-800 dark:text-slate-200">
              No Administrative Audit Activity Recorded Yet
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 max-w-lg leading-relaxed font-sans">
              Platform governance actions (such as operator account approvals, role reassignments,
              suspensions, and singleton platform bootstrap) are immutably logged to{' '}
              <code className="font-mono text-purple-600 dark:text-purple-400">
                public.audit_logs
              </code>{' '}
              with <code className="font-mono">audit_category = &apos;platform&apos;</code>.
              Operational alert triage actions are strictly isolated and not commingled here.
            </p>
          </div>
        ) : (
          /* SVG Line Chart */
          <div className="space-y-4 pt-2">
            <div className="w-full overflow-x-auto">
              <svg
                viewBox={`0 0 ${activityTimeSeries.width} ${activityTimeSeries.height}`}
                className="w-full h-44 select-none"
              >
                <defs>
                  <linearGradient id="adminActivityGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#9333ea" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#9333ea" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Horizontal reference grid lines */}
                {[0, 0.5, 1].map((ratio) => {
                  const y =
                    activityTimeSeries.padTop +
                    activityTimeSeries.plotHeight -
                    ratio * activityTimeSeries.plotHeight;
                  const labelVal = Math.round(ratio * activityTimeSeries.scaleY);
                  return (
                    <g key={ratio}>
                      <line
                        x1={activityTimeSeries.padLeft}
                        y1={y}
                        x2={activityTimeSeries.width - activityTimeSeries.padRight}
                        y2={y}
                        stroke="currentColor"
                        strokeDasharray="3 3"
                        className="text-slate-200 dark:text-slate-800"
                        strokeWidth="1"
                      />
                      <text
                        x={activityTimeSeries.padLeft - 8}
                        y={y + 3}
                        textAnchor="end"
                        className="fill-slate-400 dark:fill-slate-500 font-mono text-[9px]"
                      >
                        {labelVal}
                      </text>
                    </g>
                  );
                })}

                {/* Area Gradient Fill */}
                {activityTimeSeries.areaPath && (
                  <path
                    d={activityTimeSeries.areaPath}
                    fill="url(#adminActivityGradient)"
                  />
                )}

                {/* Line Path */}
                {activityTimeSeries.linePath && (
                  <path
                    d={activityTimeSeries.linePath}
                    fill="none"
                    stroke="#9333ea"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                )}

                {/* Data Points and Value Callouts */}
                {activityTimeSeries.points.map((pt) => (
                  <g key={pt.date} className="group">
                    <circle
                      cx={pt.x}
                      cy={pt.y}
                      r="4.5"
                      fill="#9333ea"
                      stroke="#ffffff"
                      strokeWidth="2"
                      className="cursor-pointer transition-transform hover:scale-125"
                    />
                    {/* Event count label above dot */}
                    <text
                      x={pt.x}
                      y={pt.y - 8}
                      textAnchor="middle"
                      className="fill-purple-700 dark:fill-purple-300 font-mono font-bold text-[10px]"
                    >
                      {pt.count}
                    </text>
                    {/* X-axis date label */}
                    <text
                      x={pt.x}
                      y={activityTimeSeries.height - 6}
                      textAnchor="middle"
                      className="fill-slate-500 dark:fill-slate-400 font-mono text-[9px]"
                    >
                      {pt.date.slice(5)}
                    </text>
                  </g>
                ))}
              </svg>
            </div>

            <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-800/80">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-600" />
                <span>Scope: Platform Governance Ledger</span>
              </div>
              <div>
                Active Recording Days: {activityTimeSeries.dates.length} &bull; Peak: {activityTimeSeries.maxCount} events/day
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
