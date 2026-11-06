import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  LayoutDashboard,
  FileCode,
  TrendingUp,
  Server,
  Database,
  ShieldCheck,
  Search,
  RotateCcw,
  RefreshCw,
  AlertOctagon,
  Sparkles,
  Info,
} from 'lucide-react';
import {
  SocAnalystKnowledgeRecord,
  fetchSocAnalystKnowledge,
} from '../../services/knowledgeService';
import { UserProfile } from '../../types/auth';
import { WorkspaceView } from '../layout/AppSidebar';
import {
  SocKnowledgeFilters,
  ActiveFilterChip,
  AggregatedTechnique,
} from './knowledge/types';
import {
  INITIAL_SOC_FILTERS,
  applySocKnowledgeFilters,
  extractTechniques,
} from './knowledge/filterUtils';
import { ActiveFilterChips } from './knowledge/ActiveFilterChips';
import { TechniqueDetailModal } from './knowledge/TechniqueDetailModal';
import { SocOverviewPage } from './knowledge/pages/SocOverviewPage';
import { DetectionStrategyExplorerPage } from './knowledge/pages/DetectionStrategyExplorerPage';
import { AnalyticExplorerPage } from './knowledge/pages/AnalyticExplorerPage';
import { LogSourceExplorerPage } from './knowledge/pages/LogSourceExplorerPage';
import { DataComponentExplorerPage } from './knowledge/pages/DataComponentExplorerPage';
import { TechniqueExplorerPage } from './knowledge/pages/TechniqueExplorerPage';
import { Button } from '../common/Button';

export type SocKnowledgeView =
  | 'overview'
  | 'strategies'
  | 'analytics'
  | 'log_sources'
  | 'data_components'
  | 'mitre_explorer';

interface SocAnalystWorkspaceProps {
  currentView: SocKnowledgeView;
  onNavigateView: (view: WorkspaceView) => void;
  currentUser: UserProfile;
}

export const SocAnalystWorkspace: React.FC<SocAnalystWorkspaceProps> = ({
  currentView,
  onNavigateView,
  currentUser,
}) => {
  const [records, setRecords] = useState<SocAnalystKnowledgeRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Lifted shared filter state persisting across all 6 pages
  const [filters, setFilters] = useState<SocKnowledgeFilters>(INITIAL_SOC_FILTERS);
  const [inspectTechniqueId, setInspectTechniqueId] = useState<string | null>(null);

  // Load records from public.soc_analyst_knowledge using authenticated client
  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchSocAnalystKnowledge(currentUser);
      setRecords(data);
    } catch (err: any) {
      console.error('[SocAnalystWorkspace] Failed to fetch knowledge dataset:', err);
      setError(err?.message || 'Failed to load reference knowledge dataset.');
    } finally {
      setIsLoading(false);
    }
  }, [currentUser]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Apply multi-dimensional cross-filtering
  const filteredRecords = useMemo(() => {
    return applySocKnowledgeFilters(records, filters);
  }, [records, filters]);

  // All techniques for inspection modal lookup
  const allTechniquesMap = useMemo(() => {
    const list = extractTechniques(records);
    const map = new Map<string, AggregatedTechnique>();
    for (const t of list) {
      map.set(t.id, t);
    }
    return map;
  }, [records]);

  const activeTechniqueForInspection = useMemo(() => {
    if (!inspectTechniqueId) return null;
    return allTechniquesMap.get(inspectTechniqueId) || null;
  }, [inspectTechniqueId, allTechniquesMap]);

  // Remove individual filter chip
  const handleRemoveChip = useCallback((chip: ActiveFilterChip) => {
    setFilters((prev) => {
      switch (chip.dimension) {
        case 'search':
          return { ...prev, searchQuery: '' };
        case 'tactic':
          return {
            ...prev,
            selectedTactics: prev.selectedTactics.filter((t) => t !== chip.value),
          };
        case 'platform':
          return {
            ...prev,
            selectedPlatforms: prev.selectedPlatforms.filter((p) => p !== chip.value),
          };
        case 'log_source':
          return {
            ...prev,
            selectedLogSources: prev.selectedLogSources.filter((l) => l !== chip.value),
          };
        case 'data_component':
          return {
            ...prev,
            selectedDataComponents: prev.selectedDataComponents.filter((d) => d !== chip.value),
          };
        case 'strategy':
          return {
            ...prev,
            selectedStrategies: prev.selectedStrategies.filter((s) => s !== chip.value),
          };
        default:
          return prev;
      }
    });
  }, []);

  const handleClearAllFilters = useCallback(() => {
    setFilters(INITIAL_SOC_FILTERS);
  }, []);

  // Map legacy sub-tab navigation to WorkspaceView navigation
  const handleTabNavigation = useCallback(
    (tab: string) => {
      switch (tab) {
        case 'overview':
          onNavigateView('overview');
          break;
        case 'strategies':
          onNavigateView('strategies');
          break;
        case 'analytics':
          onNavigateView('analytics');
          break;
        case 'log_sources':
        case 'log-sources':
          onNavigateView('log_sources');
          break;
        case 'data_components':
        case 'data-components':
          onNavigateView('data_components');
          break;
        case 'mitre_explorer':
        case 'techniques':
          onNavigateView('mitre_explorer');
          break;
        default:
          onNavigateView('overview');
      }
    },
    [onNavigateView]
  );

  // Meta information for header
  const viewMeta = useMemo(() => {
    switch (currentView) {
      case 'overview':
        return {
          title: 'SOC Analytics Overview',
          subtitle: 'Enterprise telemetry, MITRE ATT&CK coverage, and detection posture.',
          icon: <LayoutDashboard className="w-5 h-5 text-indigo-400" />,
        };
      case 'strategies':
        return {
          title: 'Detection Strategy Analytics',
          subtitle: 'Detection blueprints cataloged across enterprise ATT&CK techniques.',
          icon: <FileCode className="w-5 h-5 text-cyan-400" />,
        };
      case 'analytics':
        return {
          title: 'Analytic Analytics',
          subtitle: 'SIEM and EDR detection rules mapped to telemetry feeds and attack IDs.',
          icon: <TrendingUp className="w-5 h-5 text-emerald-400" />,
        };
      case 'log_sources':
        return {
          title: 'Log Source Analytics',
          subtitle: 'Telemetry data feeds, event pipelines, and technique coverage mapping.',
          icon: <Server className="w-5 h-5 text-amber-400" />,
        };
      case 'data_components':
        return {
          title: 'Data Component Analytics',
          subtitle: 'Observable telemetry elements and entity contexts mapped to techniques.',
          icon: <Database className="w-5 h-5 text-purple-400" />,
        };
      case 'mitre_explorer':
        return {
          title: 'MITRE ATT&CK Explorer',
          subtitle: 'Cataloged ATT&CK techniques, tactic alignment, and detection coverage.',
          icon: <ShieldCheck className="w-5 h-5 text-blue-400" />,
        };
      default:
        return {
          title: 'SOC Knowledge Hub',
          subtitle: 'Operational threat intelligence & detection engineering.',
          icon: <LayoutDashboard className="w-5 h-5 text-indigo-400" />,
        };
    }
  }, [currentView]);

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-slate-950 text-slate-100 overflow-y-auto">
      {/* Top Banner & Shared Filter Control Header */}
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-xs sticky top-0 z-20 px-6 py-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-slate-800/90 border border-slate-700 rounded-xl shadow-xs">
              {viewMeta.icon}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-slate-100 font-heading tracking-tight">
                  {viewMeta.title}
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800">
                  PUBLIC.SOC_ANALYST_KNOWLEDGE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{viewMeta.subtitle}</p>
            </div>
          </div>

          {/* Quick Filter Search & Refresh Actions */}
          <div className="flex items-center gap-2.5">
            <div className="relative min-w-[260px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={filters.searchQuery}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
                }
                placeholder="Global filter across all 6 pages..."
                className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded-lg pl-9 pr-8 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none transition-colors"
              />
              {filters.searchQuery && (
                <button
                  type="button"
                  onClick={() => setFilters((prev) => ({ ...prev, searchQuery: '' }))}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 text-xs"
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={loadData}
              disabled={isLoading}
              className="text-xs border-slate-700 hover:bg-slate-800 text-slate-300 shrink-0"
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            >
              Refresh
            </Button>
          </div>
        </div>

        {/* Global Active Filter Chips Bar with Shared State Recalculation */}
        <ActiveFilterChips
          filters={filters}
          totalCatalogRecords={records.length}
          filteredRecordsCount={filteredRecords.length}
          onRemoveChip={handleRemoveChip}
          onClearAll={handleClearAllFilters}
        />
      </div>

      {/* Main Page Content Body */}
      <main className="flex-1 p-6 space-y-6">
        {error && (
          <div className="p-4 bg-rose-950/50 border border-rose-800 rounded-xl text-rose-200 text-xs flex items-start gap-3">
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold text-rose-300">Dataset Fetch Error</p>
              <p className="text-rose-200">{error}</p>
              <Button
                variant="outline"
                size="sm"
                onClick={loadData}
                className="mt-2 text-xs border-rose-700 hover:bg-rose-900/60 text-rose-100"
              >
                Retry Request
              </Button>
            </div>
          </div>
        )}

        {isLoading && records.length === 0 ? (
          <div className="py-24 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
            <p className="text-sm font-semibold text-slate-300">
              Querying <code className="font-mono text-indigo-300">public.soc_analyst_knowledge</code>...
            </p>
            <p className="text-xs text-slate-500">
              Aggregating verified tactics, techniques, strategies, analytics, and log sources.
            </p>
          </div>
        ) : (
          <>
            {currentView === 'overview' && (
              <SocOverviewPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onNavigateTab={handleTabNavigation as any}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}

            {currentView === 'strategies' && (
              <DetectionStrategyExplorerPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}

            {currentView === 'analytics' && (
              <AnalyticExplorerPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}

            {currentView === 'log_sources' && (
              <LogSourceExplorerPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}

            {currentView === 'data_components' && (
              <DataComponentExplorerPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}

            {currentView === 'mitre_explorer' && (
              <TechniqueExplorerPage
                records={filteredRecords}
                allRecords={records}
                filters={filters}
                onUpdateFilters={setFilters}
                onSelectTechniqueId={setInspectTechniqueId}
              />
            )}
          </>
        )}
      </main>

      {/* Reusable Record Inspection Modal */}
      {inspectTechniqueId && (
        <TechniqueDetailModal
          technique={activeTechniqueForInspection}
          onClose={() => setInspectTechniqueId(null)}
          onFilterByTactic={(tactic: string) => {
            setFilters((prev) => {
              const exists = prev.selectedTactics.includes(tactic);
              return {
                ...prev,
                selectedTactics: exists ? prev.selectedTactics : [...prev.selectedTactics, tactic],
              };
            });
          }}
          onFilterByPlatform={(platform: string) => {
            setFilters((prev) => {
              const exists = prev.selectedPlatforms.includes(platform);
              return {
                ...prev,
                selectedPlatforms: exists
                  ? prev.selectedPlatforms
                  : [...prev.selectedPlatforms, platform],
              };
            });
          }}
        />
      )}
    </div>
  );
};
