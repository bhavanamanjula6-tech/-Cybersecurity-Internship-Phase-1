import React, { useState, useMemo, useCallback } from 'react';
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
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../services/knowledgeService';
import { UserProfile } from '../../../types/auth';
import {
  SocKnowledgeTab,
  SocKnowledgeFilters,
  ActiveFilterChip,
  AggregatedTechnique,
} from './types';
import {
  INITIAL_SOC_FILTERS,
  applySocKnowledgeFilters,
  extractTechniques,
} from './filterUtils';
import { ActiveFilterChips } from './ActiveFilterChips';
import { TechniqueDetailModal } from './TechniqueDetailModal';
import { SocOverviewPage } from './pages/SocOverviewPage';
import { DetectionStrategyExplorerPage } from './pages/DetectionStrategyExplorerPage';
import { AnalyticExplorerPage } from './pages/AnalyticExplorerPage';
import { LogSourceExplorerPage } from './pages/LogSourceExplorerPage';
import { DataComponentExplorerPage } from './pages/DataComponentExplorerPage';
import { TechniqueExplorerPage } from './pages/TechniqueExplorerPage';
import { Button } from '../../common/Button';

interface SocKnowledgeHubProps {
  records: SocAnalystKnowledgeRecord[];
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
  currentUser?: UserProfile;
  initialTab?: SocKnowledgeTab;
}

export const SocKnowledgeHub: React.FC<SocKnowledgeHubProps> = ({
  records,
  isLoading,
  error,
  onRefresh,
  currentUser,
  initialTab = 'overview',
}) => {
  const [activeTab, setActiveTab] = useState<SocKnowledgeTab>(initialTab);
  const [filters, setFilters] = useState<SocKnowledgeFilters>(INITIAL_SOC_FILTERS);
  const [inspectTechniqueId, setInspectTechniqueId] = useState<string | null>(null);

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

  const tabItems: Array<{
    id: SocKnowledgeTab;
    label: string;
    icon: React.ReactNode;
    badgeCount?: number;
  }> = [
    {
      id: 'overview',
      label: '1. SOC Overview',
      icon: <LayoutDashboard className="w-4 h-4 text-indigo-400" />,
    },
    {
      id: 'strategies',
      label: '2. Detection Strategies',
      icon: <FileCode className="w-4 h-4 text-cyan-400" />,
    },
    {
      id: 'analytics',
      label: '3. Analytics',
      icon: <TrendingUp className="w-4 h-4 text-emerald-400" />,
    },
    {
      id: 'log-sources',
      label: '4. Log Sources',
      icon: <Server className="w-4 h-4 text-amber-400" />,
    },
    {
      id: 'data-components',
      label: '5. Data Components',
      icon: <Database className="w-4 h-4 text-purple-400" />,
    },
    {
      id: 'techniques',
      label: '6. MITRE ATT&CK',
      icon: <ShieldCheck className="w-4 h-4 text-indigo-400" />,
    },
  ];

  return (
    <div className="space-y-5">
      {/* Top Banner and Navigation Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <ShieldCheck className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-slate-100">
                SOC Analyst Reference Knowledge Hub
              </h2>
              <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                public.soc_analyst_knowledge ({records.length} records)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Authoritative MITRE ATT&CK reference framework, detection strategies, analytics, log sources, and data components.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Global Search across dataset */}
            <div className="relative min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={filters.searchQuery}
                onChange={(e) => setFilters((prev) => ({ ...prev, searchQuery: e.target.value }))}
                placeholder="Global knowledge search..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              disabled={isLoading}
              className="text-xs flex items-center gap-1.5 shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              Reload
            </Button>
          </div>
        </div>

        {/* 6 Knowledge Sub-Page Tabs */}
        <div className="border-t border-slate-800 pt-3">
          <nav className="flex items-center gap-2 overflow-x-auto pb-1" aria-label="Knowledge Hub Pages">
            {tabItems.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'bg-slate-800 text-slate-100 border border-slate-700 shadow-xs'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                  role="tab"
                  aria-selected={isActive}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Active Filter Chips Bar (Synchronized across all 6 pages) */}
        <ActiveFilterChips
          filters={filters}
          onRemoveChip={handleRemoveChip}
          onClearAll={handleClearAllFilters}
          totalCatalogRecords={records.length}
          filteredRecordsCount={filteredRecords.length}
        />
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="py-16 bg-slate-900 border border-slate-800 rounded-xl flex flex-col items-center justify-center space-y-3">
          <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
          <p className="text-xs font-mono text-slate-400">
            Fetching authoritative reference dataset from Supabase...
          </p>
        </div>
      )}

      {/* Error State */}
      {!isLoading && error && (
        <div className="p-5 bg-rose-950/40 border border-rose-800 rounded-xl text-xs space-y-3">
          <div className="flex items-center gap-2 text-rose-300 font-bold">
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
            Knowledge Base Retrieval Error
          </div>
          <p className="text-rose-200/90 font-mono text-xs leading-relaxed">
            {error}
          </p>
          <div>
            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              className="text-xs border-rose-700 hover:bg-rose-900/40 text-rose-200"
            >
              Retry Database Query
            </Button>
          </div>
        </div>
      )}

      {/* Tab Page Views */}
      {!isLoading && !error && (
        <div>
          {activeTab === 'overview' && (
            <SocOverviewPage
              records={filteredRecords}
              allRecords={records}
              filters={filters}
              onUpdateFilters={setFilters}
              onNavigateTab={(tab) => setActiveTab(tab as SocKnowledgeTab)}
            />
          )}

          {activeTab === 'strategies' && (
            <DetectionStrategyExplorerPage
              records={filteredRecords}
              filters={filters}
              onUpdateFilters={setFilters}
              onSelectTechniqueId={setInspectTechniqueId}
            />
          )}

          {activeTab === 'analytics' && (
            <AnalyticExplorerPage
              records={filteredRecords}
              filters={filters}
              onUpdateFilters={setFilters}
              onSelectTechniqueId={setInspectTechniqueId}
            />
          )}

          {activeTab === 'log-sources' && (
            <LogSourceExplorerPage
              records={filteredRecords}
              filters={filters}
              onUpdateFilters={setFilters}
              onSelectTechniqueId={setInspectTechniqueId}
            />
          )}

          {activeTab === 'data-components' && (
            <DataComponentExplorerPage
              records={filteredRecords}
              filters={filters}
              onUpdateFilters={setFilters}
              onSelectTechniqueId={setInspectTechniqueId}
            />
          )}

          {activeTab === 'techniques' && (
            <TechniqueExplorerPage
              records={filteredRecords}
              filters={filters}
              onUpdateFilters={setFilters}
              onSelectTechniqueId={setInspectTechniqueId}
            />
          )}
        </div>
      )}

      {/* Technique Detail Modal (Shared across all pages) */}
      <TechniqueDetailModal
        technique={activeTechniqueForInspection}
        onClose={() => setInspectTechniqueId(null)}
        onFilterByTactic={(tactic) => {
          setFilters((prev) => ({
            ...prev,
            selectedTactics: prev.selectedTactics.includes(tactic)
              ? prev.selectedTactics
              : [...prev.selectedTactics, tactic],
          }));
          setInspectTechniqueId(null);
        }}
        onFilterByPlatform={(platform) => {
          setFilters((prev) => ({
            ...prev,
            selectedPlatforms: prev.selectedPlatforms.includes(platform)
              ? prev.selectedPlatforms
              : [...prev.selectedPlatforms, platform],
          }));
          setInspectTechniqueId(null);
        }}
        onFilterByLogSource={(logSource) => {
          setFilters((prev) => ({
            ...prev,
            selectedLogSources: prev.selectedLogSources.includes(logSource)
              ? prev.selectedLogSources
              : [...prev.selectedLogSources, logSource],
          }));
          setInspectTechniqueId(null);
        }}
      />
    </div>
  );
};
