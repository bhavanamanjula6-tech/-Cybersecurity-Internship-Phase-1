import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { MitreTactic, MitreTechnique, MitreMitigation, MitreDefenseCoverage } from '../../types/mitre';
import { SecurityAlert } from '../../types/alert';
import { UserProfile } from '../../types/auth';
import {
  fetchSecurityEngineerKnowledge,
  SecurityEngineerKnowledgeRecord,
} from '../../services/knowledgeService';
import { lookupSecurityEngineerKnowledgeForTechnique } from '../../services/relationshipService';
import { formatAttackIdDisplay } from '../../utils/mitreUtils';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { DetectionWorkbenchView } from './DetectionWorkbenchView';
import { SecurityAnalyticsView } from './SecurityAnalyticsView';
import { ImprovementRecommendationsView } from './ImprovementRecommendationsView';
import {
  computeSecurityAnalytics,
  generateImprovementRecommendations,
} from '../../services/securityAnalyticsService';
import { DetectionRuleService, DetectionRuleDraft } from '../../services/detectionRuleService';
import { DetectionRecommendation, CreateRecommendationInput } from '../../types/recommendation';
import {
  Layers,
  ShieldCheck,
  Search,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Database,
  Filter,
  Grid3X3,
  List,
  ShieldAlert,
  Info,
  Check,
  X,
  RefreshCw,
  HelpCircle,
  Eye,
  FileCode2,
  Activity,
  ArrowRight,
} from 'lucide-react';

export type CoverageStatus = 'both' | 'detection_only' | 'mitigation_only' | 'gap';

export interface TechniqueCoverageInfo {
  technique: MitreTechnique;
  hasDetection: boolean;
  hasMitigation: boolean;
  status: CoverageStatus;
  statusLabel: string;
  badgeClass: string;
}

interface SecurityEngineerDashboardProps {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  mitigations: MitreMitigation[];
  coverage: MitreDefenseCoverage[];
  isLoading?: boolean;
  onRefresh?: () => void;
  currentUser?: UserProfile;
  activeRecommendations?: DetectionRecommendation[];
  onSubmitRecommendation?: (input: CreateRecommendationInput) => Promise<void>;
  onUpdateRecommendationImplementation?: (
    recommendationId: string,
    status: 'in_progress' | 'completed',
    notes?: string,
    sigmaDraftReference?: string
  ) => Promise<void>;
  onRefreshRecommendations?: () => void;
  onSimulateAlert?: (alert: SecurityAlert) => Promise<void>;
}

export type SecurityEngineerViewMode = 'matrix' | 'list' | 'workbench' | 'analytics' | 'recommendations';

export const SecurityEngineerDashboard: React.FC<SecurityEngineerDashboardProps> = ({
  tactics,
  techniques,
  mitigations,
  coverage,
  isLoading = false,
  onRefresh,
  currentUser,
  activeRecommendations = [],
  onSubmitRecommendation,
  onUpdateRecommendationImplementation,
  onRefreshRecommendations,
  onSimulateAlert,
}) => {
  const [selectedTacticId, setSelectedTacticId] = useState<string>('all');
  const [selectedCoverageFilter, setSelectedCoverageFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(() => {
    return techniques.length > 0 ? techniques[0] : null;
  });
  const [viewMode, setViewMode] = useState<SecurityEngineerViewMode>('matrix');

  // Security Engineer Knowledge Base (public.security_engineer_knowledge) state for Defense Inspector
  const [knowledgeRecords, setKnowledgeRecords] = useState<SecurityEngineerKnowledgeRecord[]>([]);
  const [isLoadingKnowledge, setIsLoadingKnowledge] = useState<boolean>(false);
  const [knowledgeError, setKnowledgeError] = useState<string | null>(null);

  const loadKnowledge = useCallback(async () => {
    if (!currentUser) return;
    setIsLoadingKnowledge(true);
    setKnowledgeError(null);
    try {
      const records = await fetchSecurityEngineerKnowledge(currentUser);
      setKnowledgeRecords(records);
    } catch (err) {
      setKnowledgeError(
        err instanceof Error ? err.message : 'Failed to query Security Engineer reference knowledge.'
      );
      setKnowledgeRecords([]);
    } finally {
      setIsLoadingKnowledge(false);
    }
  }, [currentUser]);

  useEffect(() => {
    let isMounted = true;

    async function initialFetch() {
      if (!currentUser) return;
      setIsLoadingKnowledge(true);
      setKnowledgeError(null);
      try {
        const records = await fetchSecurityEngineerKnowledge(currentUser);
        if (!isMounted) return;
        setKnowledgeRecords(records);
      } catch (err) {
        if (!isMounted) return;
        setKnowledgeError(
          err instanceof Error ? err.message : 'Failed to query Security Engineer reference knowledge.'
        );
        setKnowledgeRecords([]);
      } finally {
        if (isMounted) {
          setIsLoadingKnowledge(false);
        }
      }
    }

    initialFetch();

    return () => {
      isMounted = false;
    };
  }, [currentUser]);

  const secEngKnowledgeLookup = useMemo(() => {
    if (!selectedTechnique?.id || knowledgeRecords.length === 0) return null;
    return lookupSecurityEngineerKnowledgeForTechnique(selectedTechnique.id, knowledgeRecords);
  }, [selectedTechnique, knowledgeRecords]);

  // Load session drafts to derive analytics and rule inventory
  const [drafts, setDrafts] = useState<DetectionRuleDraft[]>(() => {
    const loaded = DetectionRuleService.loadDraftsFromSession();
    if (loaded && loaded.length > 0) return loaded;
    return DetectionRuleService.getInitialStarterDrafts(techniques, tactics);
  });

  // Re-read session drafts on view mode change to keep in sync with workbench edits
  useEffect(() => {
    const loaded = DetectionRuleService.loadDraftsFromSession();
    if (loaded && loaded.length > 0) {
      setDrafts(loaded);
    }
  }, [viewMode]);

  // Compute deterministic security analytics and prioritized improvement recommendations
  const analytics = useMemo(() => {
    return computeSecurityAnalytics(techniques, tactics, drafts);
  }, [techniques, tactics, drafts]);

  const recommendations = useMemo(() => {
    return generateImprovementRecommendations(techniques, tactics, drafts);
  }, [techniques, tactics, drafts]);

  const handleDraftRuleForTechnique = (techId: string) => {
    const tech = techniques.find((t) => t.id === techId);
    if (tech) {
      setSelectedTechnique(tech);
    }
    setViewMode('workbench');
  };

  // Compute coverage classification for all techniques
  const coverageMap = useMemo(() => {
    const map = new Map<string, TechniqueCoverageInfo>();

    for (const tech of techniques) {
      const hasDetection = Boolean(
        tech.detectionGuidance &&
          tech.detectionGuidance.trim().length > 0 &&
          tech.dataSources.length > 0
      );
      const hasMitigation = Boolean(tech.mitigationIds && tech.mitigationIds.length > 0);

      let status: CoverageStatus = 'gap';
      let statusLabel = 'Undocumented Gap';
      let badgeClass = 'bg-slate-800 text-slate-300 border-slate-700';

      if (hasDetection && hasMitigation) {
        status = 'both';
        statusLabel = 'Detections & Mitigations';
        badgeClass =
          'bg-emerald-950/70 text-emerald-300 border-emerald-800/80 dark:bg-emerald-950/80 dark:text-emerald-300';
      } else if (hasDetection) {
        status = 'detection_only';
        statusLabel = 'Detection Strategy Only';
        badgeClass =
          'bg-cyan-950/70 text-cyan-300 border-cyan-800/80 dark:bg-cyan-950/80 dark:text-cyan-300';
      } else if (hasMitigation) {
        status = 'mitigation_only';
        statusLabel = 'Mitigation Only';
        badgeClass =
          'bg-amber-950/70 text-amber-300 border-amber-800/80 dark:bg-amber-950/80 dark:text-amber-300';
      }

      map.set(tech.id, {
        technique: tech,
        hasDetection,
        hasMitigation,
        status,
        statusLabel,
        badgeClass,
      });
    }

    return map;
  }, [techniques]);

  // Overall Coverage statistics derived strictly from actual schema records
  const stats = useMemo(() => {
    const totalTechniques = techniques.length;
    let coveredByBoth = 0;
    let coveredByDetections = 0;
    let coveredByMitigations = 0;
    let gaps = 0;

    coverageMap.forEach((info) => {
      if (info.status === 'both') {
        coveredByBoth++;
        coveredByDetections++;
        coveredByMitigations++;
      } else if (info.status === 'detection_only') {
        coveredByDetections++;
      } else if (info.status === 'mitigation_only') {
        coveredByMitigations++;
      } else {
        gaps++;
      }
    });

    const detectionPercent =
      totalTechniques > 0 ? Math.round((coveredByDetections / totalTechniques) * 100) : 0;
    const mitigationPercent =
      totalTechniques > 0 ? Math.round((coveredByMitigations / totalTechniques) * 100) : 0;
    const fullDefensePercent =
      totalTechniques > 0 ? Math.round((coveredByBoth / totalTechniques) * 100) : 0;

    return {
      totalTechniques,
      coveredByBoth,
      coveredByDetections,
      coveredByMitigations,
      gaps,
      detectionPercent,
      mitigationPercent,
      fullDefensePercent,
    };
  }, [techniques, coverageMap]);

  // Filtered techniques based on search, tactic, and coverage status
  const filteredTechniques = useMemo(() => {
    let list = [...techniques];

    if (selectedTacticId !== 'all') {
      list = list.filter((t) => t.tactics.includes(selectedTacticId));
    }

    if (selectedCoverageFilter !== 'all') {
      list = list.filter((t) => {
        const info = coverageMap.get(t.id);
        return info?.status === selectedCoverageFilter;
      });
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (t) =>
          t.id.toLowerCase().includes(q) ||
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          t.dataSources.some((ds) => ds.toLowerCase().includes(q))
      );
    }

    return list;
  }, [techniques, selectedTacticId, selectedCoverageFilter, searchQuery, coverageMap]);

  // Tactics for 2D Matrix columns
  const displayedTactics = useMemo(() => {
    if (selectedTacticId === 'all') {
      return tactics;
    }
    return tactics.filter((tac) => tac.id === selectedTacticId);
  }, [tactics, selectedTacticId]);

  // Group filtered techniques by tactic for the 2D Matrix
  const matrixColumns = useMemo(() => {
    const map = new Map<string, MitreTechnique[]>();

    for (const tac of displayedTactics) {
      const matchingTechs = filteredTechniques.filter((t) => t.tactics.includes(tac.id));
      map.set(tac.id, matchingTechs);
    }

    return map;
  }, [displayedTactics, filteredTechniques]);

  const handleSelectTechnique = (tech: MitreTechnique) => {
    setSelectedTechnique(tech);
  };

  const resetFilters = () => {
    setSelectedTacticId('all');
    setSelectedCoverageFilter('all');
    setSearchQuery('');
  };

  // Render Skeleton Loading State
  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-10 bg-slate-800 rounded w-1/3" />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-20 bg-slate-900 border border-slate-800 rounded-lg" />
          ))}
        </div>
        <div className="h-14 bg-slate-900 border border-slate-800 rounded-lg" />
        <div className="h-96 bg-slate-900 border border-slate-800 rounded-lg" />
      </div>
    );
  }

  // Error state when no tactics or techniques are loaded
  if (tactics.length === 0 || techniques.length === 0) {
    return (
      <div className="p-8 bg-slate-900 border border-rose-900/60 rounded-lg text-center space-y-3">
        <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
        <h2 className="text-base font-bold text-slate-100">MITRE Reference Taxonomy Unavailable</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          The curated MITRE ATT&CK Enterprise reference taxonomy could not be retrieved from the repository bundle.
        </p>
        {onRefresh && (
          <Button size="sm" variant="outline" onClick={onRefresh}>
            Retry Loading Taxonomy
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header and Provenance Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              Security Engineering: MITRE ATT&CK Defense Coverage
            </h1>
            <ProvenanceBadge type="authentic_mitre" label="MITRE v14.1 ENTERPRISE" />
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit attack techniques, evaluate verified detection coverage, and analyze defensive mitigations across the 2D Enterprise matrix.
          </p>
        </div>

        {onRefresh && (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="secondary" onClick={onRefresh} icon={<RefreshCw className="w-3.5 h-3.5" />}>
              Refresh Reference
            </Button>
          </div>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 block">CATALOGED TECHNIQUES</span>
          <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1 block">{stats.totalTechniques}</span>
          <span className="text-[10px] text-slate-500">Curated v14.1 Scope</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-cyan-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-blue-600 dark:text-cyan-400 block">DETECTION STRATEGIES</span>
          <span className="text-xl font-bold font-mono text-blue-700 dark:text-cyan-400 mt-1 block">
            {stats.coveredByDetections} ({stats.detectionPercent}%)
          </span>
          <span className="text-[10px] text-blue-600/70 dark:text-cyan-300/70">Verified telemetry sources</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-blue-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-blue-600 dark:text-blue-400 block">DOCUMENTED MITIGATIONS</span>
          <span className="text-xl font-bold font-mono text-blue-700 dark:text-blue-400 mt-1 block">
            {stats.coveredByMitigations} ({stats.mitigationPercent}%)
          </span>
          <span className="text-[10px] text-blue-600/70 dark:text-blue-300/70">Control guidance mapped</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-amber-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-amber-600 dark:text-amber-400 block">ACTIVE TACTICS</span>
          <span className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1 block">{tactics.length}</span>
          <span className="text-[10px] text-amber-700/70 dark:text-amber-300/70">Initial Access to Impact</span>
        </div>
      </div>

      {/* Analytics & Top Recommendation Quick Glance Banner */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs text-xs">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="inline-flex items-center gap-1 font-mono text-[11px] font-bold text-slate-800 dark:text-slate-200">
            <Activity className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
            Analytics Quick-Glance:
          </span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800">
            {drafts.length} Sigma Drafts ({analytics.ruleInventory.validSyntaxCount} Valid)
          </span>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            0 Deployed (Non-Deployed)
          </span>
          {recommendations.length > 0 && (
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-rose-600 dark:text-rose-400" />
              Top Gap: {recommendations[0].techniqueId}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setViewMode('analytics')}
            className="text-[11px] font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span>Full Analytics</span>
            <ArrowRight className="w-3 h-3" />
          </button>
          <span className="text-slate-300 dark:text-slate-700">&bull;</span>
          <button
            type="button"
            onClick={() => setViewMode('recommendations')}
            className="text-[11px] font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span>All Recommendations ({recommendations.length})</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Coverage Status Legend & Integrity Banner */}
      <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2 text-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-slate-300 font-semibold text-[11px]">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>Coverage Heatmap Legend (Distinguished strictly from available schema data):</span>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            {stats.coveredByBoth} of {stats.totalTechniques} have both Detections & Mitigations ({stats.fullDefensePercent}%)
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono pt-1">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-emerald-500 border border-emerald-400" />
            <span className="text-slate-300">Detections + Mitigations ({stats.coveredByBoth})</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-cyan-500 border border-cyan-400" />
            <span className="text-slate-300">
              Detection Strategy Only ({stats.coveredByDetections - stats.coveredByBoth})
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-amber-500 border border-amber-400" />
            <span className="text-slate-300">
              Mitigation Only ({stats.coveredByMitigations - stats.coveredByBoth})
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-slate-700 border border-slate-600" />
            <span className="text-slate-400">Undocumented Gap ({stats.gaps})</span>
          </div>
        </div>
      </div>

      {/* Filter and View Mode Toolbar */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2.5 shadow-xs">
        <div className="flex flex-col lg:flex-row gap-2.5 items-stretch lg:items-center justify-between">
          {/* Search box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search technique ID, name, keyword, or data source (e.g. T1059, PowerShell, LSASS, Sysmon)..."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
            />
          </div>

          {/* Quick Filter Selectors */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Tactic Dropdown */}
            <select
              value={selectedTacticId}
              onChange={(e) => setSelectedTacticId(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              aria-label="Filter techniques by tactic"
            >
              <option value="all">All Tactics ({tactics.length})</option>
              {tactics.map((tac) => (
                <option key={tac.id} value={tac.id}>
                  {tac.id}: {tac.name}
                </option>
              ))}
            </select>

            {/* Coverage Status Dropdown */}
            <select
              value={selectedCoverageFilter}
              onChange={(e) => setSelectedCoverageFilter(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              aria-label="Filter techniques by coverage status"
            >
              <option value="all">All Coverage Levels</option>
              <option value="both">Both Detections & Mitigations</option>
              <option value="detection_only">Detection Strategy Only</option>
              <option value="mitigation_only">Mitigation Only</option>
              <option value="gap">Undocumented Gaps</option>
            </select>

            {(searchQuery || selectedTacticId !== 'all' || selectedCoverageFilter !== 'all') && (
              <Button size="xs" variant="ghost" onClick={resetFilters}>
                Clear Filters
              </Button>
            )}

            {/* View Mode Toggle: 2D Matrix vs Catalog List vs Detection Workbench vs Analytics vs Recommendations */}
            <div className="flex flex-wrap items-center rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-950 p-0.5 ml-auto gap-0.5">
              <button
                type="button"
                onClick={() => setViewMode('matrix')}
                className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer transition ${
                  viewMode === 'matrix'
                    ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="View as 2D ATT&CK Matrix Heatmap"
                aria-label="2D Matrix Heatmap view"
              >
                <Grid3X3 className="w-3.5 h-3.5" />
                <span>2D Matrix</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer transition ${
                  viewMode === 'list'
                    ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="View as Technique Catalog List"
                aria-label="Technique Catalog List view"
              >
                <List className="w-3.5 h-3.5" />
                <span>Catalog</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('workbench')}
                className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer transition ${
                  viewMode === 'workbench'
                    ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="Detection Engineering Rule Workbench (Sigma Templates)"
                aria-label="Detection Engineering Workbench view"
              >
                <FileCode2 className="w-3.5 h-3.5" />
                <span>Workbench</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('analytics')}
                className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer transition ${
                  viewMode === 'analytics'
                    ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="Security Analytics & Coverage Accounting"
                aria-label="Security Analytics view"
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Analytics</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('recommendations')}
                className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer transition ${
                  viewMode === 'recommendations'
                    ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
                title="Prioritized Defensive Improvement Recommendations"
                aria-label="Defensive Improvement Recommendations view"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Recommendations</span>
                {recommendations.length > 0 && (
                  <span className="px-1 py-0.2 rounded-full text-[9px] font-mono font-bold bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300">
                    {recommendations.length}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      {viewMode === 'workbench' ? (
        <DetectionWorkbenchView
          techniques={techniques}
          tactics={tactics}
          initialSelectedTechnique={selectedTechnique}
          onDispatchSimulatedAlert={onSimulateAlert}
          userRole={currentUser?.role}
        />
      ) : viewMode === 'analytics' ? (
        <SecurityAnalyticsView
          analytics={analytics}
          techniques={techniques}
          tactics={tactics}
          onDraftRuleForTechnique={handleDraftRuleForTechnique}
        />
      ) : viewMode === 'recommendations' ? (
        <ImprovementRecommendationsView
          recommendations={recommendations}
          onSelectTechniqueForDraft={handleDraftRuleForTechnique}
          currentUser={currentUser}
          activeRecommendations={activeRecommendations}
          onSubmitRecommendation={onSubmitRecommendation}
          onUpdateImplementation={onUpdateRecommendationImplementation}
          availableDrafts={drafts}
          onRefreshActiveRecommendations={onRefreshRecommendations}
        />
      ) : filteredTechniques.length === 0 ? (
        <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-center space-y-3 shadow-xs">
          <Filter className="w-8 h-8 text-slate-400 mx-auto" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            No Techniques Match Filter Criteria
          </h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            No ATT&CK techniques match the current combination of search keyword, tactic selection, and coverage status.
          </p>
          <Button size="xs" variant="outline" onClick={resetFilters}>
            Reset Filters
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
          {/* Center/Left: 2D Matrix Heatmap OR Catalog List */}
          <div className="lg:col-span-2 space-y-4">
            {viewMode === 'matrix' ? (
              /* 2D MITRE ATT&CK Matrix Heatmap View */
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden shadow-xs">
                <div className="p-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-800 dark:text-slate-300 font-bold uppercase flex items-center gap-1.5">
                    <Grid3X3 className="w-4 h-4 text-cyan-400" />
                    2D ATT&CK Matrix Heatmap ({displayedTactics.length} Tactics • {filteredTechniques.length} Matching Techniques)
                  </span>
                  <span className="text-[11px] text-slate-500 hidden sm:inline">
                    Click any technique cell to inspect defense coverage
                  </span>
                </div>

                {/* Horizontal Scrollable Multi-Column 2D Matrix Container */}
                <div
                  className="overflow-x-auto p-4 focus:outline-none"
                  tabIndex={0}
                  role="region"
                  aria-label="Interactive 2D MITRE ATT&CK Matrix"
                >
                  <div className="flex gap-3 min-w-[760px] pb-2">
                    {displayedTactics.map((tactic) => {
                      const colTechniques = matrixColumns.get(tactic.id) || [];

                      return (
                        <div
                          key={tactic.id}
                          className="flex-1 min-w-[155px] max-w-[210px] bg-slate-50/70 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 rounded-lg flex flex-col shrink-0"
                        >
                          {/* Tactic Column Header */}
                          <div className="p-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-100/80 dark:bg-slate-900/90 rounded-t-lg">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-mono font-bold text-blue-700 dark:text-cyan-400">
                                {tactic.id}
                              </span>
                              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-bold">
                                {colTechniques.length}
                              </span>
                            </div>
                            <h4 className="text-xs font-bold text-slate-900 dark:text-slate-200 mt-1 truncate" title={tactic.name}>
                              {tactic.name}
                            </h4>
                          </div>

                          {/* Column Technique Cells (2nd Dimension) */}
                          <div className="p-2 space-y-2 flex-1">
                            {colTechniques.length === 0 ? (
                              <div className="p-3 text-center text-[10px] text-slate-400 dark:text-slate-600 italic">
                                No cataloged techniques in curated reference scope
                              </div>
                            ) : (
                              colTechniques.map((tech) => {
                                const info = coverageMap.get(tech.id);
                                const isSelected = selectedTechnique?.id === tech.id;

                                return (
                                  <button
                                    key={`${tactic.id}-${tech.id}`}
                                    type="button"
                                    onClick={() => handleSelectTechnique(tech)}
                                    className={`w-full text-left p-2 rounded-md border text-xs transition cursor-pointer flex flex-col justify-between gap-1.5 focus:outline-none ${
                                      isSelected
                                        ? 'bg-blue-50/90 dark:bg-slate-800 ring-2 ring-blue-500 dark:ring-cyan-400 shadow-sm border-blue-400 dark:border-cyan-500'
                                        : info?.status === 'both'
                                        ? 'bg-emerald-50/60 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900/60 hover:border-emerald-400'
                                        : info?.status === 'detection_only'
                                        ? 'bg-blue-50/60 dark:bg-cyan-950/30 border-blue-200 dark:border-cyan-900/60 hover:border-cyan-400'
                                        : info?.status === 'mitigation_only'
                                        ? 'bg-amber-50/60 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900/60 hover:border-amber-400'
                                        : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-700'
                                    }`}
                                    aria-label={`Technique ${tech.id}: ${tech.name}. Coverage: ${info?.statusLabel}`}
                                  >
                                    <div className="flex items-center justify-between w-full">
                                      <span className="font-mono text-[11px] font-bold text-slate-900 dark:text-slate-100">
                                        {tech.id}
                                      </span>
                                      <span
                                        className={`w-2 h-2 rounded-full ${
                                          info?.status === 'both'
                                            ? 'bg-emerald-500'
                                            : info?.status === 'detection_only'
                                            ? 'bg-cyan-500'
                                            : info?.status === 'mitigation_only'
                                            ? 'bg-amber-500'
                                            : 'bg-slate-600'
                                        }`}
                                        title={info?.statusLabel}
                                      />
                                    </div>

                                    <span className="text-[11px] font-medium text-slate-800 dark:text-slate-200 line-clamp-2 leading-tight">
                                      {tech.name}
                                    </span>

                                    {/* Micro Indicators */}
                                    <div className="flex items-center gap-1 text-[9px] font-mono text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200/60 dark:border-slate-800/60 w-full">
                                      <span title={`${tech.dataSources.length} detection telemetry sources`}>
                                        {tech.dataSources.length} src
                                      </span>
                                      <span>•</span>
                                      <span title={`${tech.mitigationIds.length} defensive mitigations mapped`}>
                                        {tech.mitigationIds.length} mit
                                      </span>
                                    </div>
                                  </button>
                                );
                              })
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              /* Technique Catalog List View (Preserved) */
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden shadow-xs">
                <div className="p-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-800 dark:text-slate-300 font-bold uppercase flex items-center gap-1.5">
                    <List className="w-4 h-4 text-blue-400" />
                    Enterprise Techniques ({filteredTechniques.length})
                  </span>
                  <span className="text-slate-500 text-[11px]">Select technique to inspect defense details</span>
                </div>
                <div className="divide-y divide-slate-200 dark:divide-slate-800/80 max-h-[600px] overflow-y-auto">
                  {filteredTechniques.map((tech) => {
                    const isSelected = selectedTechnique?.id === tech.id;
                    const info = coverageMap.get(tech.id);

                    return (
                      <div
                        key={tech.id}
                        onClick={() => handleSelectTechnique(tech)}
                        className={`p-3 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition cursor-pointer text-xs space-y-1.5 ${
                          isSelected
                            ? 'bg-blue-50/80 dark:bg-slate-800/80 ring-1 ring-inset ring-blue-500/50 dark:ring-cyan-500/50'
                            : ''
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-blue-700 dark:text-cyan-400 bg-blue-50 dark:bg-cyan-950 px-1.5 py-0.5 rounded border border-blue-200 dark:border-cyan-800">
                              {tech.id}
                            </span>
                            <span className="font-semibold text-slate-900 dark:text-slate-100">{tech.name}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            {info && (
                              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${info.badgeClass}`}>
                                {info.statusLabel}
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-2">{tech.description}</p>
                        <div className="flex flex-wrap gap-1 text-[10px] font-mono text-slate-500 pt-1">
                          <span>Data Sources:</span>
                          {tech.dataSources.map((ds, i) => (
                            <span key={i} className="text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-950 px-1 rounded">
                              {ds}
                            </span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Right: Selected Technique Defense Inspector */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-4 shadow-xs sticky top-4">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-2 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 block font-bold">
                  DEFENSE INSPECTOR
                </span>
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                  {selectedTechnique ? `${selectedTechnique.id}: ${selectedTechnique.name}` : 'Select a Technique'}
                </h3>
              </div>
              {selectedTechnique && coverageMap.get(selectedTechnique.id) && (
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                    coverageMap.get(selectedTechnique.id)!.badgeClass
                  }`}
                >
                  {coverageMap.get(selectedTechnique.id)!.statusLabel}
                </span>
              )}
            </div>

            {selectedTechnique ? (
              <div className="space-y-4 text-xs">
                {/* Tactics Mapping */}
                <div>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block mb-1">
                    MAPPED TACTICS ({selectedTechnique.tactics.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedTechnique.tactics.map((tId) => {
                      const tObj = tactics.find((t) => t.id === tId);
                      return (
                        <span
                          key={tId}
                          className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800"
                        >
                          {tId} {tObj ? `• ${tObj.name}` : ''}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {/* Overview */}
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block font-bold">
                    TECHNIQUE OVERVIEW
                  </span>
                  <p className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">
                    {selectedTechnique.description}
                  </p>
                </div>

                {/* Platforms */}
                <div>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block mb-1">
                    TARGET PLATFORMS
                  </span>
                  <div className="flex flex-wrap gap-1 text-[10px] font-mono">
                    {selectedTechnique.platforms.map((p) => (
                      <span
                        key={p}
                        className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Detection Guidance */}
                <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-cyan-200 dark:border-cyan-900/60 rounded-lg space-y-1.5">
                  <span className="text-[10px] font-mono text-blue-600 dark:text-cyan-400 uppercase font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Verified Detection Telemetry Guidance
                  </span>
                  <p className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">
                    {selectedTechnique.detectionGuidance || 'No specific detection guidance documented in this baseline.'}
                  </p>

                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] font-mono text-slate-400 block mb-1">Telemetry Data Sources:</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedTechnique.dataSources.map((ds, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-900 text-slate-800 dark:text-slate-300 text-[10px] font-mono"
                        >
                          {ds}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="pt-2">
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => setViewMode('workbench')}
                      className="w-full text-blue-700 dark:text-cyan-400 border-cyan-500/30 hover:bg-cyan-950/30 font-mono text-xs"
                      icon={<FileCode2 className="w-3.5 h-3.5" />}
                    >
                      Draft Sigma Rule in Workbench
                    </Button>
                  </div>
                </div>

                {/* Mapped Mitigations & Unmitigated Gaps */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block font-bold">
                      {secEngKnowledgeLookup
                        ? `Defensive Mitigations (${secEngKnowledgeLookup.mitigations.length})`
                        : `Mapped Defensive Mitigations (${selectedTechnique.mitigationIds.length})`}
                    </span>
                    {secEngKnowledgeLookup && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                        public.security_engineer_knowledge
                      </span>
                    )}
                  </div>

                  {secEngKnowledgeLookup ? (
                    secEngKnowledgeLookup.mitigations.length > 0 ? (
                      <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                        {secEngKnowledgeLookup.mitigations.map((m) => (
                          <div
                            key={m.id}
                            className="p-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-[11px] space-y-0.5"
                          >
                            <div className="flex items-center justify-between text-blue-700 dark:text-cyan-300 font-mono font-semibold">
                              <span>
                                {m.id}: {m.name}
                              </span>
                              <a
                                href={`https://attack.mitre.org/mitigations/${m.id}/`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[10px] text-slate-500 hover:text-blue-600 dark:text-slate-400 dark:hover:text-cyan-300 flex items-center gap-0.5"
                              >
                                MITRE <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            </div>
                            <p className="text-slate-600 dark:text-slate-400 text-[10px] leading-normal">
                              {m.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 bg-rose-50/70 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 rounded-md space-y-1">
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300">
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
                          Unmitigated Coverage Gap
                        </div>
                        <p className="text-[10px] text-slate-600 dark:text-slate-400 leading-normal">
                          This ATT&CK technique has no documented mitigations mapped in public.security_engineer_knowledge (part of the 111 verified unmitigated gaps).
                        </p>
                      </div>
                    )
                  ) : selectedTechnique.mitigationIds.length === 0 ? (
                    <p className="text-slate-500 italic text-[11px] p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                      No mitigations mapped in current reference baseline.
                    </p>
                  ) : (
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {selectedTechnique.mitigationIds.map((mId) => {
                        const mit = mitigations.find((m) => m.id === mId);
                        return (
                          <div
                            key={mId}
                            className="p-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-[11px] space-y-0.5"
                          >
                            <div className="flex items-center justify-between text-blue-700 dark:text-cyan-300 font-mono font-semibold">
                              <span>
                                {mId}: {mit?.name || 'Enterprise Mitigation'}
                              </span>
                              {mit?.sourceUrl && (
                                <a
                                  href={mit.sourceUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-[10px] text-slate-500 hover:text-blue-600 dark:text-slate-400 dark:hover:text-cyan-300 flex items-center gap-0.5"
                                >
                                  MITRE <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                              )}
                            </div>
                            {mit?.description && (
                              <p className="text-slate-600 dark:text-slate-400 text-[10px] leading-normal">
                                {mit.description}
                              </p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* ATT&CK Graph Relationships (Distinguished from Application Alert IDs) */}
                {secEngKnowledgeLookup && secEngKnowledgeLookup.relationships.length > 0 && (
                  <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase font-bold block">
                      ATT&CK Relationship Endpoints ({secEngKnowledgeLookup.relationships.length})
                    </span>
                    <span className="text-[10px] text-slate-500 dark:text-slate-400 block italic">
                      Taxonomy graph endpoints (addressed_source_id / addressed_target_id) — distinct from Alert IDs.
                    </span>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {secEngKnowledgeLookup.relationships.map((rel, idx) => (
                        <div
                          key={idx}
                          className="p-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-[10px] font-mono flex items-center justify-between"
                        >
                          <span className="text-blue-600 dark:text-cyan-400">{rel.sourceId || 'Source'}</span>
                          <span className="text-slate-400">→ [{rel.mappingType || 'mitigates'}] →</span>
                          <span className="text-emerald-600 dark:text-emerald-400">{rel.targetId || 'Target'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* External MITRE Link */}
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                  <a
                    href={selectedTechnique.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-1.5"
                  >
                    View Official MITRE Enterprise Page <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic py-8 text-center">
                Click any technique cell in the 2D matrix to inspect detection strategies and mitigation guidance.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
