import React, { useMemo, useState, useEffect, useCallback } from 'react';
import { SecurityAlert, AlertStatus } from '../../types/alert';
import { MitreTactic, MitreTechnique } from '../../types/mitre';
import { UserProfile } from '../../types/auth';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { AlertMetricsService } from '../../services/alertMetricsService';
import {
  fetchSocAnalystKnowledge,
  aggregateTechniquesByTactic,
  aggregateLogSources,
  SocAnalystKnowledgeRecord,
  TacticAggregation,
  LogSourceAggregation,
} from '../../services/knowledgeService';
import {
  AlertOctagon,
  ShieldAlert,
  Clock,
  Layers,
  ArrowRight,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Info,
  Server,
  RefreshCw,
  TrendingUp,
  Timer,
  BarChart2,
  HelpCircle,
  Database,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { SocKnowledgeHub } from './knowledge/SocKnowledgeHub';

interface AnalystOverviewDashboardProps {
  alerts: SecurityAlert[];
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  currentUser?: UserProfile;
  onNavigateToQueue: () => void;
  onSelectAlertForInvestigation: (alert: SecurityAlert) => void;
  onRefresh?: () => void;
  isLoading?: boolean;
}

export const AnalystOverviewDashboard: React.FC<AnalystOverviewDashboardProps> = ({
  alerts,
  tactics,
  techniques,
  currentUser,
  onNavigateToQueue,
  onSelectAlertForInvestigation,
  onRefresh,
  isLoading = false,
}) => {
  const [selectedIntervalIndex, setSelectedIntervalIndex] = useState<number | null>(null);

  // MITRE ATT&CK Knowledge & Detection Coverage state
  const [knowledgeRecords, setKnowledgeRecords] = useState<SocAnalystKnowledgeRecord[]>([]);
  const [isLoadingKnowledge, setIsLoadingKnowledge] = useState<boolean>(true);
  const [knowledgeError, setKnowledgeError] = useState<string | null>(null);
  const [showAllLogSources, setShowAllLogSources] = useState<boolean>(false);
  const [showAllTactics, setShowAllTactics] = useState<boolean>(false);

  // Core metrics derived strictly from passed alert fixtures
  const metrics = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter((a) => a.severity === 'critical').length;
    const high = alerts.filter((a) => a.severity === 'high').length;
    const medium = alerts.filter((a) => a.severity === 'medium').length;
    const low = alerts.filter((a) => a.severity === 'low').length;
    const info = alerts.filter((a) => a.severity === 'informational').length;

    const newAlerts = alerts.filter((a) => a.status === 'new').length;
    const inTriage = alerts.filter((a) => a.status === 'in_triage').length;
    const escalated = alerts.filter((a) => a.status === 'escalated').length;
    const resolved = alerts.filter((a) => a.status === 'resolved').length;
    const falsePositive = alerts.filter((a) => a.status === 'false_positive').length;

    const requiresUrgentInvestigation = alerts.filter(
      (a) => (a.status === 'new' || a.status === 'in_triage') && (a.severity === 'critical' || a.severity === 'high')
    );

    // MITRE Technique mapping frequency
    const techniqueCounts: Record<string, number> = {};
    alerts.forEach((a) => {
      if (a.mitreTechniqueId) {
        techniqueCounts[a.mitreTechniqueId] = (techniqueCounts[a.mitreTechniqueId] || 0) + 1;
      }
    });

    const topTechniques = Object.entries(techniqueCounts)
      .map(([techId, count]) => {
        const found = techniques.find((t) => t.id === techId);
        return {
          id: techId,
          name: found ? found.name : techId,
          count,
        };
      })
      .sort((a, b) => b.count - a.count);

    return {
      total,
      severity: { critical, high, medium, low, info },
      status: { newAlerts, inTriage, escalated, resolved, falsePositive },
      requiresUrgentInvestigation,
      topTechniques,
    };
  }, [alerts, techniques]);

  // 24-Hour alert intake trend computation
  const intakeTrend = useMemo(() => {
    return AlertMetricsService.calculate24hIntakeTrend(alerts);
  }, [alerts]);

  // Defensible MTTA & MTTR calculations
  const mttaMetric = useMemo(() => {
    return AlertMetricsService.calculateMTTA(alerts);
  }, [alerts]);

  const mttrMetric = useMemo(() => {
    return AlertMetricsService.calculateMTTR(alerts);
  }, [alerts]);

  // Calculate highest bucket count for chart scaling
  const maxBucketCount = useMemo(() => {
    const counts = intakeTrend.buckets.map((b) => b.count);
    return Math.max(...counts, 1);
  }, [intakeTrend]);

  // Load real reference knowledge records from public.soc_analyst_knowledge
  const loadKnowledge = useCallback(async () => {
    if (!currentUser) return;
    setIsLoadingKnowledge(true);
    setKnowledgeError(null);
    try {
      const records = await fetchSocAnalystKnowledge(currentUser);
      setKnowledgeRecords(records);
    } catch (err: any) {
      setKnowledgeError(err?.message || 'Failed to query SOC Analyst knowledge database.');
      setKnowledgeRecords([]);
    } finally {
      setIsLoadingKnowledge(false);
    }
  }, [currentUser]);

  useEffect(() => {
    let isMounted = true;
    if (!currentUser) return;

    setIsLoadingKnowledge(true);
    setKnowledgeError(null);

    fetchSocAnalystKnowledge(currentUser)
      .then((records) => {
        if (isMounted) {
          setKnowledgeRecords(records);
          setIsLoadingKnowledge(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setKnowledgeError(err?.message || 'Failed to query SOC Analyst knowledge database.');
          setKnowledgeRecords([]);
          setIsLoadingKnowledge(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [currentUser]);

  // Aggregated distributions for Chart A (Tactics) and Chart B (Log Sources)
  const tacticDistribution = useMemo(() => {
    return aggregateTechniquesByTactic(knowledgeRecords);
  }, [knowledgeRecords]);

  const logSourceDistribution = useMemo(() => {
    return aggregateLogSources(knowledgeRecords);
  }, [knowledgeRecords]);

  const displayedTactics = useMemo(() => {
    if (showAllTactics || tacticDistribution.length <= 10) {
      return tacticDistribution;
    }
    return tacticDistribution.slice(0, 10);
  }, [tacticDistribution, showAllTactics]);

  const maxTacticCount = useMemo(() => {
    if (displayedTactics.length === 0) return 1;
    return Math.max(...displayedTactics.map((t) => t.count), 1);
  }, [displayedTactics]);

  const maxLogSourceCount = useMemo(() => {
    if (logSourceDistribution.length === 0) return 1;
    return Math.max(...logSourceDistribution.map((l) => l.count), 1);
  }, [logSourceDistribution]);

  const displayedLogSources = useMemo(() => {
    if (showAllLogSources || logSourceDistribution.length <= 10) {
      return logSourceDistribution;
    }
    return logSourceDistribution.slice(0, 10);
  }, [logSourceDistribution, showAllLogSources]);

  return (
    <div className="space-y-6">
      {/* Header and Provenance Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <AlertOctagon className="w-5 h-5 text-indigo-400" />
              SOC Analyst Operations Overview
            </h1>
            <span className="px-2 py-0.5 text-xs font-medium rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
              Tier 1/2 Console
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated queue status, active threat telemetry breakdown, and triage velocity metrics.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {onRefresh && (
            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              disabled={isLoading}
              className="text-xs flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh Telemetry
            </Button>
          )}
          <Button
            variant="primary"
            size="sm"
            onClick={onNavigateToQueue}
            className="text-xs flex items-center gap-1.5"
          >
            Open Alert Queue ({metrics.total})
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <ProvenanceBadge
          type="synthetic_demo"
          label="SYNTHETIC DEMO FIXTURES (PHASE 1)"
        />
        <span className="text-xs text-slate-400">
          All metrics and incident records displayed are derived from local synthetic demonstration fixtures. Zero connection to live production sensors.
        </span>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Alert Queue</span>
            <AlertOctagon className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2 font-mono">{metrics.total}</div>
          <div className="text-xs text-slate-500 mt-1">
            {metrics.status.newAlerts} pending initial review
          </div>
        </div>

        <div className="bg-slate-900 border border-rose-900/40 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-rose-400">Critical / High Alerts</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-300 mt-2 font-mono">
            {metrics.severity.critical + metrics.severity.high}
          </div>
          <div className="text-xs text-rose-400/80 mt-1">
            {metrics.severity.critical} Critical • {metrics.severity.high} High
          </div>
        </div>

        <div className="bg-slate-900 border border-amber-900/40 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-amber-400">In Active Triage</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-2 font-mono">
            {metrics.status.inTriage}
          </div>
          <div className="text-xs text-amber-400/80 mt-1">
            {metrics.status.escalated} escalated to IR
          </div>
        </div>

        <div className="bg-slate-900 border border-emerald-900/40 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-emerald-400">Resolved / Closed</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-2 font-mono">
            {metrics.status.resolved + metrics.status.falsePositive}
          </div>
          <div className="text-xs text-emerald-400/80 mt-1">
            {metrics.status.falsePositive} false positive suppressed
          </div>
        </div>
      </div>

      {/* 24-Hour Alert-Intake Trend & Triage Velocity Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: 24-Hour Alert-Intake Trend Visualization */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <div>
              <div className="flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-indigo-400" />
                <h2 className="text-sm font-semibold text-slate-200">
                  24-Hour Alert-Intake Trend
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                  4h Intervals
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Distribution of security alerts ingested across the active 24-hour observation window.
              </p>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
              <span className="inline-block w-2 h-2 rounded-xs bg-rose-500 mr-0.5" /> Critical
              <span className="inline-block w-2 h-2 rounded-xs bg-amber-500 mr-0.5 ml-1" /> High
              <span className="inline-block w-2 h-2 rounded-xs bg-yellow-500 mr-0.5 ml-1" /> Med
              <span className="inline-block w-2 h-2 rounded-xs bg-blue-500 mr-0.5 ml-1" /> Low
            </div>
          </div>

          {/* Window Information Banner */}
          <div className="p-2.5 bg-slate-950/70 border border-slate-800 rounded mb-4 text-[11px] text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <span className="text-slate-300 font-medium">Observation Window: </span>
              <span className="font-mono text-slate-300">
                {new Date(intakeTrend.windowStartIso).toUTCString().slice(5, 22)} UTC
              </span>
              <span className="mx-1.5 text-slate-600">→</span>
              <span className="font-mono text-slate-300">
                {new Date(intakeTrend.windowEndIso).toUTCString().slice(5, 22)} UTC
              </span>
              {intakeTrend.isAnchoredToTelemetry && (
                <span className="ml-2 text-[10px] text-cyan-400 font-mono">
                  (Anchored to Telemetry Horizon)
                </span>
              )}
            </div>
            <div className="shrink-0 text-slate-400 font-mono text-[10px]">
              {intakeTrend.totalWithinWindow} in window
              {intakeTrend.invalidTimestampCount > 0 && (
                <span className="text-amber-400 ml-1.5">
                  ({intakeTrend.invalidTimestampCount} invalid timestamps)
                </span>
              )}
            </div>
          </div>

          {!intakeTrend.hasUsableData ? (
            <div className="py-12 text-center text-slate-500 text-xs italic">
              No usable alert timestamp telemetry available in current queue.
            </div>
          ) : (
            <div>
              {/* Responsive SVG / Column Bar Chart */}
              <div
                className="grid grid-cols-6 gap-2 sm:gap-3 items-end h-44 pt-6 pb-2 px-1 border-b border-slate-800"
                role="region"
                aria-label="24-hour alert-intake trend bar chart"
              >
                {intakeTrend.buckets.map((bucket) => {
                  const isSelected = selectedIntervalIndex === bucket.index;
                  const heightPercent =
                    bucket.count > 0 ? Math.max((bucket.count / maxBucketCount) * 100, 14) : 4;

                  return (
                    <button
                      key={bucket.index}
                      type="button"
                      onClick={() =>
                        setSelectedIntervalIndex(isSelected ? null : bucket.index)
                      }
                      className={`group relative flex flex-col items-center justify-end h-full w-full rounded focus:outline-none transition cursor-pointer ${
                        isSelected ? 'bg-slate-800/60 ring-1 ring-cyan-500/50' : 'hover:bg-slate-800/30'
                      }`}
                      aria-label={`Interval ${bucket.label}: ${bucket.count} alerts`}
                    >
                      {/* Count label atop column */}
                      <span className="text-[10px] font-mono font-bold text-slate-300 mb-1">
                        {bucket.count > 0 ? bucket.count : '0'}
                      </span>

                      {/* Bar Container */}
                      <div className="w-full max-w-[42px] bg-slate-950 rounded-t overflow-hidden flex flex-col-reverse justify-start border border-slate-700/60 transition-all">
                        <div
                          style={{ height: `${heightPercent}%` }}
                          className="w-full flex flex-col-reverse transition-all duration-300"
                        >
                          {/* Segmented by severity */}
                          {bucket.criticalCount > 0 && (
                            <div
                              style={{
                                height: `${(bucket.criticalCount / bucket.count) * 100}%`,
                              }}
                              className="w-full bg-rose-500"
                              title={`${bucket.criticalCount} Critical`}
                            />
                          )}
                          {bucket.highCount > 0 && (
                            <div
                              style={{
                                height: `${(bucket.highCount / bucket.count) * 100}%`,
                              }}
                              className="w-full bg-amber-500"
                              title={`${bucket.highCount} High`}
                            />
                          )}
                          {bucket.mediumCount > 0 && (
                            <div
                              style={{
                                height: `${(bucket.mediumCount / bucket.count) * 100}%`,
                              }}
                              className="w-full bg-yellow-500"
                              title={`${bucket.mediumCount} Medium`}
                            />
                          )}
                          {bucket.lowCount > 0 && (
                            <div
                              style={{
                                height: `${(bucket.lowCount / bucket.count) * 100}%`,
                              }}
                              className="w-full bg-blue-500"
                              title={`${bucket.lowCount} Low`}
                            />
                          )}
                          {bucket.infoCount > 0 && (
                            <div
                              style={{
                                height: `${(bucket.infoCount / bucket.count) * 100}%`,
                              }}
                              className="w-full bg-slate-500"
                              title={`${bucket.infoCount} Info`}
                            />
                          )}
                          {bucket.count === 0 && (
                            <div className="w-full h-1 bg-slate-800" />
                          )}
                        </div>
                      </div>

                      {/* X-Axis Interval Label */}
                      <span className="mt-2 text-[10px] font-mono text-slate-400 truncate w-full text-center">
                        {bucket.label}
                      </span>
                    </button>
                  );
                })}
              </div>

              {/* Selected Interval Detail Panel */}
              {selectedIntervalIndex !== null && (
                <div className="mt-3 p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">
                      Interval Details: {intakeTrend.buckets[selectedIntervalIndex].label} UTC
                    </span>
                    <button
                      onClick={() => setSelectedIntervalIndex(null)}
                      className="text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      Close Details
                    </button>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono pt-1 text-slate-300">
                    <div>Total: {intakeTrend.buckets[selectedIntervalIndex].count}</div>
                    <div className="text-rose-400">
                      Critical: {intakeTrend.buckets[selectedIntervalIndex].criticalCount}
                    </div>
                    <div className="text-amber-400">
                      High: {intakeTrend.buckets[selectedIntervalIndex].highCount}
                    </div>
                    <div className="text-yellow-400">
                      Medium: {intakeTrend.buckets[selectedIntervalIndex].mediumCount}
                    </div>
                  </div>
                  {intakeTrend.buckets[selectedIntervalIndex].alertIds.length > 0 && (
                    <div className="text-[10px] text-slate-400 font-mono truncate">
                      Alert IDs: {intakeTrend.buckets[selectedIntervalIndex].alertIds.join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* Accessible Summary Table for Assistive Tech */}
              <div className="sr-only">
                <table>
                  <caption>24-Hour Alert-Intake Distribution</caption>
                  <thead>
                    <tr>
                      <th scope="col">Interval</th>
                      <th scope="col">Total Alerts</th>
                      <th scope="col">Critical</th>
                      <th scope="col">High</th>
                      <th scope="col">Medium</th>
                    </tr>
                  </thead>
                  <tbody>
                    {intakeTrend.buckets.map((b) => (
                      <tr key={b.index}>
                        <td>{b.label}</td>
                        <td>{b.count}</td>
                        <td>{b.criticalCount}</td>
                        <td>{b.highCount}</td>
                        <td>{b.mediumCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Defensible MTTA & MTTR Triage Velocity Metrics */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-slate-200">
                  Triage Velocity Metrics
                </h2>
              </div>
              <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                Defensible Evaluation
              </span>
            </div>

            {/* MTTA Metric Card */}
            <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Timer className="w-3.5 h-3.5 text-blue-400" />
                  Mean Time to Acknowledge (MTTA)
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                  {mttaMetric.unit}
                </span>
              </div>

              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-slate-100">
                  {mttaMetric.formattedValue}
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  ({mttaMetric.contributingRecords} of {mttaMetric.totalRecords} records evaluated)
                </span>
              </div>

              <div className="text-[10px] text-slate-400 leading-relaxed border-t border-slate-900 pt-1.5">
                <span className="text-slate-300 font-medium">Window:</span> {mttaMetric.measurementWindow}
                <p className="mt-1 text-slate-500 italic">
                  {mttaMetric.reason}
                </p>
              </div>
            </div>

            {/* MTTR Metric Card */}
            <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Mean Time to Resolve (MTTR)
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                  {mttrMetric.unit}
                </span>
              </div>

              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-slate-100">
                  {mttrMetric.formattedValue}
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  ({mttrMetric.contributingRecords} of {mttrMetric.totalRecords} records evaluated)
                </span>
              </div>

              <div className="text-[10px] text-slate-400 leading-relaxed border-t border-slate-900 pt-1.5">
                <span className="text-slate-300 font-medium">Window:</span> {mttrMetric.measurementWindow}
                <p className="mt-1 text-slate-500 italic">
                  {mttrMetric.reason}
                </p>
              </div>
            </div>

            {/* Schema Telemetry Note */}
            <div className="p-2.5 bg-slate-950/50 border border-slate-800/70 rounded text-[10px] text-slate-400 flex items-start gap-1.5">
              <Info className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
              <span>
                <strong>Telemetry Integrity Policy:</strong> Elapsed wall-clock time is strictly forbidden as a proxy for MTTR when explicit resolution event timestamps are unpopulated.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK & Telemetry Reference Knowledge Hub (The Six Knowledge Pages) */}
      <section aria-label="Reference Knowledge Hub">
        <SocKnowledgeHub
          records={knowledgeRecords}
          isLoading={isLoadingKnowledge}
          error={knowledgeError}
          onRefresh={loadKnowledge}
          currentUser={currentUser}
        />
      </section>

      {/* Main Content Grid: Urgent Triage Priority & MITRE Mapping */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Urgent Attention Queue */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-xs">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                Alerts Requiring Priority Investigation ({metrics.requiresUrgentInvestigation.length})
              </h2>
              <span className="text-xs text-slate-500 font-mono">Unresolved Critical / High</span>
            </div>

            {metrics.requiresUrgentInvestigation.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs italic">
                No unresolved high or critical alerts in the active queue.
              </div>
            ) : (
              <div className="space-y-2.5">
                {metrics.requiresUrgentInvestigation.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-3.5 bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs font-bold text-slate-300">{alert.id}</span>
                        <span
                          className={`px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded ${
                            alert.severity === 'critical'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {alert.severity}
                        </span>
                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {alert.status}
                        </span>
                        {alert.mitreTechniqueId && (
                          <span className="font-mono text-[10px] text-blue-400 bg-blue-950/50 px-1 rounded border border-blue-900/60">
                            {alert.mitreTechniqueId}
                          </span>
                        )}
                      </div>
                      <p className="text-xs font-medium text-slate-200 truncate">{alert.title}</p>
                      <p className="text-[11px] text-slate-400 flex items-center gap-2">
                        <Server className="w-3 h-3 text-slate-500" />
                        Host: <span className="font-mono text-slate-300">{alert.hostName}</span>
                        <span>•</span>
                        IP: <span className="font-mono text-slate-300">{alert.sourceIp}</span>
                      </p>
                    </div>

                    <div className="shrink-0 flex items-center gap-2">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => onSelectAlertForInvestigation(alert)}
                        className="text-xs whitespace-nowrap"
                      >
                        Deep Triage
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Severity & Status Breakdown Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow-xs">
              <h3 className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-slate-400" />
                Severity Distribution
              </h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-rose-400 font-medium">Critical</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.severity.critical}</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-amber-400 font-medium">High</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.severity.high}</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-yellow-400 font-medium">Medium</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.severity.medium}</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-blue-400 font-medium">Low</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.severity.low}</span>
                </div>
                <div className="flex justify-between items-center py-1">
                  <span className="text-slate-400 font-medium">Informational</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.severity.info}</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow-xs">
              <h3 className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                Workflow Lifecycle Status
              </h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-slate-300">New (Unexamined)</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.status.newAlerts}</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-blue-300">In Triage (Active)</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.status.inTriage}</span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/60">
                  <span className="text-amber-300">Escalated to IR</span>
                  <span className="font-mono font-bold text-slate-200">{metrics.status.escalated}</span>
                </div>
                <div className="flex justify-between items-center py-1">
                  <span className="text-emerald-300">Resolved / Closed</span>
                  <span className="font-mono font-bold text-slate-200">
                    {metrics.status.resolved + metrics.status.falsePositive}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Col: MITRE ATT&CK Technique Frequency & Queue Shortcuts */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow-xs">
            <h3 className="text-xs font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              MITRE Technique Correlation
            </h3>
            <p className="text-[11px] text-slate-400 mb-3">
              Distribution of adversary techniques mapped across current active telemetry.
            </p>

            {metrics.topTechniques.length === 0 ? (
              <div className="py-4 text-center text-xs text-slate-500 italic">
                No MITRE techniques mapped in current alerts.
              </div>
            ) : (
              <div className="space-y-2">
                {metrics.topTechniques.map((item) => (
                  <div
                    key={item.id}
                    className="p-2.5 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="font-mono text-xs font-bold text-blue-300">{item.id}</div>
                      <div className="text-[11px] text-slate-400 truncate max-w-[180px]">{item.name}</div>
                    </div>
                    <span className="px-2 py-0.5 rounded-full bg-blue-950 text-blue-300 border border-blue-800 font-mono text-xs font-bold">
                      {item.count} {item.count === 1 ? 'alert' : 'alerts'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3 shadow-xs">
            <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
              <Info className="w-4 h-4 text-slate-400" />
              Operational Protocol Notice
            </h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              SOC Analysts evaluate alert evidence deterministically, document forensic hypotheses in immutable analyst notes, and authorize simulated containment actions per approved SOPs.
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={onNavigateToQueue}
              className="w-full text-xs justify-center"
            >
              Browse Full Triage Queue
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
