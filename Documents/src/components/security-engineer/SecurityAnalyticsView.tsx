import React from 'react';
import {
  Layers,
  ShieldCheck,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
  Clock,
  ExternalLink,
  Plus,
  Activity,
  Lock,
} from 'lucide-react';
import { MitreTechnique, MitreTactic } from '../../types/mitre';
import { SecurityAnalyticsSummary } from '../../services/securityAnalyticsService';
import { ProvenanceBadge } from '../common/ProvenanceBadge';

interface SecurityAnalyticsViewProps {
  analytics: SecurityAnalyticsSummary;
  techniques: MitreTechnique[];
  tactics: MitreTactic[];
  onDraftRuleForTechnique?: (techniqueId: string) => void;
  className?: string;
}

export const SecurityAnalyticsView: React.FC<SecurityAnalyticsViewProps> = ({
  analytics,
  techniques,
  tactics,
  onDraftRuleForTechnique,
  className = '',
}) => {
  const { coverage, ruleInventory, telemetry } = analytics;

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold font-mono uppercase text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
              Security Analytics & Coverage Accounting
            </h2>
            <ProvenanceBadge type="authentic_mitre" label="CURATED V14.1 SCOPE" />
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Objective measurement of catalog detection guidance, authored draft rules, and active telemetry correlation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            READ-ONLY ANALYSIS
          </span>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Catalog Detection Coverage */}
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1.5 uppercase font-bold text-[10px]">
              <ShieldCheck className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
              Catalog Detections
            </span>
            <span className="text-[10px] font-mono font-bold text-blue-700 dark:text-cyan-300">
              {coverage.detectionPercentage}%
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
            {coverage.techniquesWithDetectionGuidance} / {coverage.totalTechniques}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Techniques with documented telemetry sources
          </div>
        </div>

        {/* Card 2: Documented Mitigations */}
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1.5 uppercase font-bold text-[10px]">
              <Layers className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              Documented Mitigations
            </span>
            <span className="text-[10px] font-mono font-bold text-blue-700 dark:text-blue-300">
              {coverage.mitigationPercentage}%
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
            {coverage.techniquesWithMitigations} / {coverage.totalTechniques}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Techniques with defensive control mappings
          </div>
        </div>

        {/* Card 3: Authored Sigma Draft Rules */}
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1.5 uppercase font-bold text-[10px]">
              <FileCode2 className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
              Authored Sigma Drafts
            </span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
              WORKBENCH
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-purple-700 dark:text-purple-300">
            {ruleInventory.totalDrafts}{' '}
            <span className="text-xs font-normal text-slate-400">
              ({ruleInventory.validSyntaxCount} Valid)
            </span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Session rules; 100% strictly non-deployed
          </div>
        </div>

        {/* Card 4: Deployed Detections (Truthful 0) */}
        <div className="p-3.5 bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1.5 uppercase font-bold text-[10px]">
              <Lock className="w-3.5 h-3.5 text-slate-500" />
              Deployed Detections
            </span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
              NON-DEPLOYED
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-800 dark:text-slate-200">
            0 <span className="text-xs font-normal text-slate-400">Active</span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Zero active SIEM rules (authoring sandbox only)
          </div>
        </div>
      </div>

      {/* Honest Telemetry Limitation Notice */}
      <div className="p-3 bg-blue-50/50 dark:bg-blue-950/20 border border-blue-100 dark:border-blue-900/40 rounded-xl flex items-start gap-2.5 text-xs text-blue-900 dark:text-blue-300">
        <Info className="w-4 h-4 text-blue-600 dark:text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold">
            Telemetry Accounting & Non-Fabrication Invariant:
          </p>
          <p className="text-[11px] leading-relaxed text-blue-800 dark:text-blue-300/90 font-sans">
            Trigger velocity ({telemetry.triggerVelocity}), false-positive rates ({telemetry.falsePositiveRate}), and detection drift ({telemetry.detectionDrift}) are strictly documented as unmeasured. The platform does not fabricate speculative metrics in the absence of a live EDR/SIEM telemetry ingestion pipeline.
          </p>
        </div>
      </div>

      {/* Two Column Layout: Rule Inventory Breakdown vs Coverage Gaps */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Column 1: Detection Rule Inventory & Validation */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-2">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <FileCode2 className="w-4 h-4 text-purple-600 dark:text-purple-400" />
              Rule Inventory & Validation Status
            </h3>
            <span className="text-[10px] font-mono text-slate-400">
              {ruleInventory.totalDrafts} Total Drafts
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
            <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <span className="text-[10px] text-slate-400 block">DRAFT</span>
              <span className="text-base font-bold text-slate-800 dark:text-slate-200">
                {ruleInventory.draftStatusCounts.draft}
              </span>
            </div>
            <div className="p-2 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60">
              <span className="text-[10px] text-amber-700 dark:text-amber-300 block">EXPERIMENTAL</span>
              <span className="text-base font-bold text-amber-800 dark:text-amber-200">
                {ruleInventory.draftStatusCounts.experimental}
              </span>
            </div>
            <div className="p-2 rounded-lg bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-200 dark:border-cyan-800/60">
              <span className="text-[10px] text-cyan-700 dark:text-cyan-300 block">REVIEW</span>
              <span className="text-base font-bold text-cyan-800 dark:text-cyan-200">
                {ruleInventory.draftStatusCounts.review}
              </span>
            </div>
          </div>

          {/* Validation Status */}
          <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500 dark:text-slate-400">Structural Syntax Validation:</span>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 text-[11px] text-emerald-600 dark:text-emerald-400 font-bold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {ruleInventory.validSyntaxCount} Valid
                </span>
                {ruleInventory.invalidSyntaxCount > 0 && (
                  <span className="inline-flex items-center gap-1 text-[11px] text-rose-600 dark:text-rose-400 font-bold">
                    <XCircle className="w-3.5 h-3.5" />
                    {ruleInventory.invalidSyntaxCount} Invalid
                  </span>
                )}
              </div>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
              Structural validation checks mandatory Sigma specification headers: title, id, status, description, logsource, detection, and condition.
            </p>
          </div>

          {/* Active Alert Correlation */}
          <div className="space-y-1.5 pt-1">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold block">
              Observed Synthetic Telemetry Correlation ({telemetry.observedCorrelatedAlertsCount} Alerts)
            </span>
            <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
              {telemetry.techniquesWithObservedAlerts.map((t) => (
                <div
                  key={t.techniqueId}
                  className="flex items-center justify-between p-1.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-[11px] font-mono"
                >
                  <span className="font-bold text-blue-700 dark:text-cyan-400">{t.techniqueId}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-slate-500">
                      {t.alertCount} Alert{t.alertCount === 1 ? '' : 's'}
                    </span>
                    <span className="px-1 py-0.2 rounded text-[9px] uppercase font-bold bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                      {t.severities.join(', ')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Column 2: Uncovered Techniques / Missing Authored Drafts */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-2">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              Techniques Without Authored Rules
            </h3>
            <span className="text-[10px] font-mono text-amber-700 dark:text-amber-400">
              {coverage.techniquesWithoutAuthoredDrafts.length} Uncovered
            </span>
          </div>

          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
            Catalog techniques with documented detection guidance that lack an active Sigma rule draft in the engineering workbench:
          </p>

          <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
            {coverage.techniquesWithoutAuthoredDrafts.map((tech) => (
              <div
                key={tech.id}
                className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-0.5 truncate flex-1">
                  <div className="flex items-center gap-1.5 font-mono">
                    <span className="font-bold text-slate-900 dark:text-slate-100">{tech.id}</span>
                    <span className="text-[10px] text-slate-400">({tech.tactics[0]})</span>
                  </div>
                  <div className="text-[11px] text-slate-600 dark:text-slate-400 truncate">
                    {tech.name}
                  </div>
                </div>

                {onDraftRuleForTechnique && (
                  <button
                    type="button"
                    onClick={() => onDraftRuleForTechnique(tech.id)}
                    className="px-2 py-1 rounded text-[11px] font-mono font-semibold bg-white dark:bg-slate-800 hover:bg-purple-50 hover:text-purple-700 dark:hover:bg-purple-950 dark:hover:text-purple-300 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 transition flex items-center gap-1 shrink-0 cursor-pointer shadow-xs"
                    title={`Create Sigma draft template for ${tech.id}`}
                  >
                    <Plus className="w-3 h-3" />
                    <span>Draft Rule</span>
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
