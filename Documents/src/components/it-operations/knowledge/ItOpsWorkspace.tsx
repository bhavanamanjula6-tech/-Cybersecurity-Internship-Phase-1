import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { RefreshCw, AlertTriangle, X, Filter } from 'lucide-react';
import { UserProfile } from '../../../types/auth';
import {
  fetchItOperationsKnowledge,
  ItOperationsKnowledgeRecord,
} from '../../../services/knowledgeService';
import {
  ItOpsKnowledgeView,
  ItOpsKnowledgeFilters,
} from './types';
import {
  INITIAL_ITOPS_FILTERS,
  applyItOpsKnowledgeFilters,
  buildItOpsActiveFilterChips,
} from './itOpsFilterUtils';
import { ItOpsOverviewPage } from './pages/ItOpsOverviewPage';
import { TechniquePlatformExplorerPage } from './pages/TechniquePlatformExplorerPage';
import { MitigationExplorerPage } from './pages/MitigationExplorerPage';

interface ItOpsWorkspaceProps {
  currentView: ItOpsKnowledgeView;
  onNavigateView: (view: ItOpsKnowledgeView) => void;
  currentUser: UserProfile;
}

export const ItOpsWorkspace: React.FC<ItOpsWorkspaceProps> = ({
  currentView,
  onNavigateView,
  currentUser,
}) => {
  const [records, setRecords] = useState<ItOperationsKnowledgeRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Shared lifted filter state
  const [filters, setFilters] = useState<ItOpsKnowledgeFilters>(INITIAL_ITOPS_FILTERS);

  const loadData = useCallback(async () => {
    if (!currentUser) return;
    setIsLoading(true);
    setError(null);
    try {
      const fetched = await fetchItOperationsKnowledge(currentUser);
      setRecords(fetched);
    } catch (err: any) {
      console.error('Failed to load IT Operations knowledge:', err);
      setError(err?.message || 'Failed to query IT Operations reference knowledge.');
      setRecords([]);
    } finally {
      setIsLoading(false);
    }
  }, [currentUser]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Filtered records based on active shared filters
  const filteredRecords = useMemo(
    () => applyItOpsKnowledgeFilters(records, filters),
    [records, filters]
  );

  // Active filter chips
  const activeChips = useMemo(() => buildItOpsActiveFilterChips(filters), [filters]);

  const handleRemoveChip = (chip: { dimension: string; value: string }) => {
    setFilters((prev) => {
      switch (chip.dimension) {
        case 'search':
          return { ...prev, searchQuery: '' };
        case 'platform':
          return {
            ...prev,
            selectedPlatforms: prev.selectedPlatforms.filter((p) => p !== chip.value),
          };
        case 'tactic':
          return {
            ...prev,
            selectedTactics: prev.selectedTactics.filter((t) => t !== chip.value),
          };
        case 'mitigation':
          return {
            ...prev,
            selectedMitigations: prev.selectedMitigations.filter((m) => m !== chip.value),
          };
        default:
          return prev;
      }
    });
  };

  const handleClearAllChips = () => {
    setFilters(INITIAL_ITOPS_FILTERS);
  };

  if (isLoading) {
    return (
      <div className="py-20 flex flex-col items-center justify-center space-y-4">
        <RefreshCw className="w-8 h-8 text-amber-500 animate-spin" />
        <div className="text-center space-y-1">
          <p className="text-sm font-semibold text-slate-200">
            Querying public.it_operations_knowledge...
          </p>
          <p className="text-xs text-slate-500 font-mono">
            Retrieving verified ATT&CK technique and mitigation records from Supabase
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 bg-rose-950/40 border border-rose-800 rounded-xl max-w-2xl mx-auto my-12 space-y-4">
        <div className="flex items-center gap-2.5 text-rose-400 font-bold">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>IT Operations Knowledge Query Failure</span>
        </div>
        <p className="text-xs font-mono text-rose-200/90 leading-relaxed">{error}</p>
        <button
          type="button"
          onClick={loadData}
          className="px-4 py-2 bg-rose-900/60 hover:bg-rose-800 text-rose-200 rounded-lg text-xs font-semibold transition"
        >
          Retry Knowledge Query
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Active Filter Chips Bar (when filters are active) */}
      {activeChips.length > 0 && (
        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-2 shadow-xs">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400 uppercase font-bold flex items-center gap-1 mr-1">
              <Filter className="w-3 h-3 text-amber-400" />
              Active Filters:
            </span>
            {activeChips.map((chip) => (
              <span
                key={chip.id}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono bg-slate-800 text-slate-200 border border-slate-700"
              >
                <span>{chip.label}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveChip(chip)}
                  className="text-slate-400 hover:text-slate-100 p-0.5 rounded transition"
                  aria-label={`Remove filter ${chip.label}`}
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-slate-400">
              Matching <strong className="text-amber-400">{filteredRecords.length}</strong> of{' '}
              {records.length} records
            </span>
            <button
              type="button"
              onClick={handleClearAllChips}
              className="text-amber-400 hover:text-amber-300 font-semibold cursor-pointer underline"
            >
              Clear All
            </button>
          </div>
        </div>
      )}

      {/* Render Active View */}
      {currentView === 'itops_overview' && (
        <ItOpsOverviewPage
          records={filteredRecords}
          filters={filters}
          onUpdateFilters={setFilters}
          onSelectTechniqueId={(tid) => {
            setFilters((prev) => ({ ...prev, searchQuery: tid }));
            onNavigateView('itops_techniques');
          }}
          onSelectMitigationId={(mid) => {
            setFilters((prev) => ({ ...prev, searchQuery: mid }));
            onNavigateView('itops_mitigations');
          }}
        />
      )}

      {currentView === 'itops_techniques' && (
        <TechniquePlatformExplorerPage
          records={filteredRecords}
          filters={filters}
          onUpdateFilters={setFilters}
          onSelectMitigationId={(mid) => {
            setFilters((prev) => ({ ...prev, searchQuery: mid }));
            onNavigateView('itops_mitigations');
          }}
        />
      )}

      {currentView === 'itops_mitigations' && (
        <MitigationExplorerPage
          records={filteredRecords}
          filters={filters}
          onUpdateFilters={setFilters}
          onSelectTechniqueId={(tid) => {
            setFilters((prev) => ({ ...prev, searchQuery: tid }));
            onNavigateView('itops_techniques');
          }}
        />
      )}
    </div>
  );
};
